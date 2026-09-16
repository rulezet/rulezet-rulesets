rule TTP_XOR_MULT_DOSStub_5447 {
  strings:
    $key_5447 = { 00 2f [2] 74 37 [2] 33 35 [2] 74 24 [2] 3a 28 [2] 36 22 [2] 21 29 [2] 3a 67 [2] 07 }

  condition:
    any of them
}