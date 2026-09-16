rule TTP_XOR_WriteProcessMemory_9df7 {
  strings:
    $key_9df7 = { ca 85 [2] f8 a7 [2] fe 92 [2] d0 92 [2] ef 8e }

  condition:
    any of them
}