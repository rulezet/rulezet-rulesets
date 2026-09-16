rule TTP_XOR_WriteProcessMemory_d8b4 {
  strings:
    $key_d8b4 = { 8f c6 [2] bd e4 [2] bb d1 [2] 95 d1 [2] aa cd }

  condition:
    any of them
}