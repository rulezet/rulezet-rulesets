rule TTP_XOR_MULT_DOSStub_73b7 {
  strings:
    $key_73b7 = { 27 df [2] 53 c7 [2] 14 c5 [2] 53 d4 [2] 1d d8 [2] 11 d2 [2] 06 d9 [2] 1d 97 [2] 20 }

  condition:
    any of them
}