rule TTP_XOR_WriteProcessMemory_9de7 {
  strings:
    $key_9de7 = { ca 95 [2] f8 b7 [2] fe 82 [2] d0 82 [2] ef 9e }

  condition:
    any of them
}