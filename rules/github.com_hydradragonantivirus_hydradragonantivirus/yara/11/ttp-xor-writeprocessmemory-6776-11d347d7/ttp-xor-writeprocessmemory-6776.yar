rule TTP_XOR_WriteProcessMemory_6776 {
  strings:
    $key_6776 = { 30 04 [2] 02 26 [2] 04 13 [2] 2a 13 [2] 15 0f }

  condition:
    any of them
}