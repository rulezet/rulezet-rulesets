rule TTP_XOR_MULT_DOSStub_6466 {
  strings:
    $key_6466 = { 30 0e [2] 44 16 [2] 03 14 [2] 44 05 [2] 0a 09 [2] 06 03 [2] 11 08 [2] 0a 46 [2] 37 }

  condition:
    any of them
}