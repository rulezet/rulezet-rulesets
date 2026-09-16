rule TTP_XOR_MULT_DOSStub_63b7 {
  strings:
    $key_63b7 = { 37 df [2] 43 c7 [2] 04 c5 [2] 43 d4 [2] 0d d8 [2] 01 d2 [2] 16 d9 [2] 0d 97 [2] 30 }

  condition:
    any of them
}