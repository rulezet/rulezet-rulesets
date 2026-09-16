rule TTP_XOR_MULT_DOSStub_73c0 {
  strings:
    $key_73c0 = { 27 a8 [2] 53 b0 [2] 14 b2 [2] 53 a3 [2] 1d af [2] 11 a5 [2] 06 ae [2] 1d e0 [2] 20 }

  condition:
    any of them
}