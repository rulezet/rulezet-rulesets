rule TTP_XOR_WriteProcessMemory_ddd2 {
  strings:
    $key_ddd2 = { 8a a0 [2] b8 82 [2] be b7 [2] 90 b7 [2] af ab }

  condition:
    any of them
}