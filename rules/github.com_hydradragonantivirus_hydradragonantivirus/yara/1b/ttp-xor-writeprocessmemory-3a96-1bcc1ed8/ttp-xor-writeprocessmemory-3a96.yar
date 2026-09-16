rule TTP_XOR_WriteProcessMemory_3a96 {
  strings:
    $key_3a96 = { 6d e4 [2] 5f c6 [2] 59 f3 [2] 77 f3 [2] 48 ef }

  condition:
    any of them
}