rule TTP_XOR_MULT_DOSStub_6470 {
  strings:
    $key_6470 = { 30 18 [2] 44 00 [2] 03 02 [2] 44 13 [2] 0a 1f [2] 06 15 [2] 11 1e [2] 0a 50 [2] 37 }

  condition:
    any of them
}