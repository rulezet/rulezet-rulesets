rule TTP_XOR_WriteProcessMemory_ddd5 {
  strings:
    $key_ddd5 = { 8a a7 [2] b8 85 [2] be b0 [2] 90 b0 [2] af ac }

  condition:
    any of them
}