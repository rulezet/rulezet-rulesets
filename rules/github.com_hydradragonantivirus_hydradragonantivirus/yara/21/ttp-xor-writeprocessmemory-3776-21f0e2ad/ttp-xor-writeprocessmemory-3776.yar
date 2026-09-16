rule TTP_XOR_WriteProcessMemory_3776 {
  strings:
    $key_3776 = { 60 04 [2] 52 26 [2] 54 13 [2] 7a 13 [2] 45 0f }

  condition:
    any of them
}