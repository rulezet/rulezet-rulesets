rule TTP_XOR_WriteProcessMemory_dfc5 {
  strings:
    $key_dfc5 = { 88 b7 [2] ba 95 [2] bc a0 [2] 92 a0 [2] ad bc }

  condition:
    any of them
}