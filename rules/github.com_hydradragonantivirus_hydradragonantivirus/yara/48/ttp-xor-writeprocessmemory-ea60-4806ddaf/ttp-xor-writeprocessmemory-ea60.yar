rule TTP_XOR_WriteProcessMemory_ea60 {
  strings:
    $key_ea60 = { bd 12 [2] 8f 30 [2] 89 05 [2] a7 05 [2] 98 19 }

  condition:
    any of them
}