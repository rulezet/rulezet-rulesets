rule TTP_XOR_WriteProcessMemory_9d57 {
  strings:
    $key_9d57 = { ca 25 [2] f8 07 [2] fe 32 [2] d0 32 [2] ef 2e }

  condition:
    any of them
}