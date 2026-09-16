rule TTP_XOR_MULT_DOSStub_4357 {
  strings:
    $key_4357 = { 17 3f [2] 63 27 [2] 24 25 [2] 63 34 [2] 2d 38 [2] 21 32 [2] 36 39 [2] 2d 77 [2] 10 }

  condition:
    any of them
}