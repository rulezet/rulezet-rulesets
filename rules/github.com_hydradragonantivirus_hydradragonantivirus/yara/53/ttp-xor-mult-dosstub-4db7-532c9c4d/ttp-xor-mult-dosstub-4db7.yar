rule TTP_XOR_MULT_DOSStub_4db7 {
  strings:
    $key_4db7 = { 19 df [2] 6d c7 [2] 2a c5 [2] 6d d4 [2] 23 d8 [2] 2f d2 [2] 38 d9 [2] 23 97 [2] 1e }

  condition:
    any of them
}