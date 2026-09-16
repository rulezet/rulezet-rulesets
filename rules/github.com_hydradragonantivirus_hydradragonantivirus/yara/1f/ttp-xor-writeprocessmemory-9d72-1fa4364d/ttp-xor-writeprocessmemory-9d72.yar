rule TTP_XOR_WriteProcessMemory_9d72 {
  strings:
    $key_9d72 = { ca 00 [2] f8 22 [2] fe 17 [2] d0 17 [2] ef 0b }

  condition:
    any of them
}