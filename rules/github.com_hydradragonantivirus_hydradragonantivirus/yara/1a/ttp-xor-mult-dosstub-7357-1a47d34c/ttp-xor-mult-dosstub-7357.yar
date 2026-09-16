rule TTP_XOR_MULT_DOSStub_7357 {
  strings:
    $key_7357 = { 27 3f [2] 53 27 [2] 14 25 [2] 53 34 [2] 1d 38 [2] 11 32 [2] 06 39 [2] 1d 77 [2] 20 }

  condition:
    any of them
}