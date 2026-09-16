rule TTP_XOR_WriteProcessMemory_ea50 {
  strings:
    $key_ea50 = { bd 22 [2] 8f 00 [2] 89 35 [2] a7 35 [2] 98 29 }

  condition:
    any of them
}