rule TTP_XOR_WriteProcessMemory_dfc2 {
  strings:
    $key_dfc2 = { 88 b0 [2] ba 92 [2] bc a7 [2] 92 a7 [2] ad bb }

  condition:
    any of them
}