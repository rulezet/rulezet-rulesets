rule TTP_XOR_WriteProcessMemory_dfc6 {
  strings:
    $key_dfc6 = { 88 b4 [2] ba 96 [2] bc a3 [2] 92 a3 [2] ad bf }

  condition:
    any of them
}