rule TTP_XOR_MULT_DOSStub_7db7 {
  strings:
    $key_7db7 = { 29 df [2] 5d c7 [2] 1a c5 [2] 5d d4 [2] 13 d8 [2] 1f d2 [2] 08 d9 [2] 13 97 [2] 2e }

  condition:
    any of them
}