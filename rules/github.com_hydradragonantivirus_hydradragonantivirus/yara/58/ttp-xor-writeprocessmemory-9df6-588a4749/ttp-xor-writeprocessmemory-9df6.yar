rule TTP_XOR_WriteProcessMemory_9df6 {
  strings:
    $key_9df6 = { ca 84 [2] f8 a6 [2] fe 93 [2] d0 93 [2] ef 8f }

  condition:
    any of them
}