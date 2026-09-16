rule TTP_XOR_MULT_DOSStub_7fb3 {
  strings:
    $key_7fb3 = { 2b db [2] 5f c3 [2] 18 c1 [2] 5f d0 [2] 11 dc [2] 1d d6 [2] 0a dd [2] 11 93 [2] 2c }

  condition:
    any of them
}