rule TTP_XOR_WriteProcessMemory_ea36 {
  strings:
    $key_ea36 = { bd 44 [2] 8f 66 [2] 89 53 [2] a7 53 [2] 98 4f }

  condition:
    any of them
}