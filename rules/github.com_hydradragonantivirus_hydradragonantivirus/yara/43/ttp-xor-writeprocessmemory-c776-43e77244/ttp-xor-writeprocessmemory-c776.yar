rule TTP_XOR_WriteProcessMemory_c776 {
  strings:
    $key_c776 = { 90 04 [2] a2 26 [2] a4 13 [2] 8a 13 [2] b5 0f }

  condition:
    any of them
}