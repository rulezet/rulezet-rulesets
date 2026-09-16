rule TTP_XOR_WriteProcessMemory_9d53 {
  strings:
    $key_9d53 = { ca 21 [2] f8 03 [2] fe 36 [2] d0 36 [2] ef 2a }

  condition:
    any of them
}