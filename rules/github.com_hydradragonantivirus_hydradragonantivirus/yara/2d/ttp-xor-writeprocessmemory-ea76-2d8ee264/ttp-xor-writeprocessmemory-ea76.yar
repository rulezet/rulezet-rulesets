rule TTP_XOR_WriteProcessMemory_ea76 {
  strings:
    $key_ea76 = { bd 04 [2] 8f 26 [2] 89 13 [2] a7 13 [2] 98 0f }

  condition:
    any of them
}