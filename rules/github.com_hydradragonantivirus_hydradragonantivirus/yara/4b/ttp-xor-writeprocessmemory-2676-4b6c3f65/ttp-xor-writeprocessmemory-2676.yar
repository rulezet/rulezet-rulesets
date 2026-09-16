rule TTP_XOR_WriteProcessMemory_2676 {
  strings:
    $key_2676 = { 71 04 [2] 43 26 [2] 45 13 [2] 6b 13 [2] 54 0f }

  condition:
    any of them
}