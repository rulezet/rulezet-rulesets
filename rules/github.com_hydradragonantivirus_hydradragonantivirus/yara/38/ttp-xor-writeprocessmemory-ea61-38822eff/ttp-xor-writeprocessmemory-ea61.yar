rule TTP_XOR_WriteProcessMemory_ea61 {
  strings:
    $key_ea61 = { bd 13 [2] 8f 31 [2] 89 04 [2] a7 04 [2] 98 18 }

  condition:
    any of them
}