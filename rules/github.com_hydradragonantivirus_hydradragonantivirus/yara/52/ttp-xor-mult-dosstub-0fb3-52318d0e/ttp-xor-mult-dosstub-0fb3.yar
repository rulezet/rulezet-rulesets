rule TTP_XOR_MULT_DOSStub_0fb3 {
  strings:
    $key_0fb3 = { 5b db [2] 2f c3 [2] 68 c1 [2] 2f d0 [2] 61 dc [2] 6d d6 [2] 7a dd [2] 61 93 [2] 5c }

  condition:
    any of them
}