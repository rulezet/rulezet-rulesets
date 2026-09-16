rule TTP_XOR_MULT_DOSStub_5457 {
  strings:
    $key_5457 = { 00 3f [2] 74 27 [2] 33 25 [2] 74 34 [2] 3a 38 [2] 36 32 [2] 21 39 [2] 3a 77 [2] 07 }

  condition:
    any of them
}