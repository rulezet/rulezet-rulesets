rule TTP_XOR_MULT_DOSStub_6370 {
  strings:
    $key_6370 = { 37 18 [2] 43 00 [2] 04 02 [2] 43 13 [2] 0d 1f [2] 01 15 [2] 16 1e [2] 0d 50 [2] 30 }

  condition:
    any of them
}