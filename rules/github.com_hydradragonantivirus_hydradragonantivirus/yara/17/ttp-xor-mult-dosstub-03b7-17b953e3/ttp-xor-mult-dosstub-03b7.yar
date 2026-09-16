rule TTP_XOR_MULT_DOSStub_03b7 {
  strings:
    $key_03b7 = { 57 df [2] 23 c7 [2] 64 c5 [2] 23 d4 [2] 6d d8 [2] 61 d2 [2] 76 d9 [2] 6d 97 [2] 50 }

  condition:
    any of them
}