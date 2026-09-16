rule TTP_XOR_MULT_DOSStub_dab7 {
  strings:
    $key_dab7 = { 8e df [2] fa c7 [2] bd c5 [2] fa d4 [2] b4 d8 [2] b8 d2 [2] af d9 [2] b4 97 [2] 89 }

  condition:
    any of them
}