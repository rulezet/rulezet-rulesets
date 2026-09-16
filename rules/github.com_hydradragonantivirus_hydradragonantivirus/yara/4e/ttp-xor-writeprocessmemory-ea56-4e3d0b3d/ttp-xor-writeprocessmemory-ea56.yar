rule TTP_XOR_WriteProcessMemory_ea56 {
  strings:
    $key_ea56 = { bd 24 [2] 8f 06 [2] 89 33 [2] a7 33 [2] 98 2f }

  condition:
    any of them
}