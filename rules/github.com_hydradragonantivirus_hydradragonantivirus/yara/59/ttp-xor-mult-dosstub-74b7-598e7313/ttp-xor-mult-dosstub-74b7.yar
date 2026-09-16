rule TTP_XOR_MULT_DOSStub_74b7 {
  strings:
    $key_74b7 = { 20 df [2] 54 c7 [2] 13 c5 [2] 54 d4 [2] 1a d8 [2] 16 d2 [2] 01 d9 [2] 1a 97 [2] 27 }

  condition:
    any of them
}