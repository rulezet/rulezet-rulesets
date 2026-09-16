rule TTP_XOR_WriteProcessMemory_9d17 {
  strings:
    $key_9d17 = { ca 65 [2] f8 47 [2] fe 72 [2] d0 72 [2] ef 6e }

  condition:
    any of them
}