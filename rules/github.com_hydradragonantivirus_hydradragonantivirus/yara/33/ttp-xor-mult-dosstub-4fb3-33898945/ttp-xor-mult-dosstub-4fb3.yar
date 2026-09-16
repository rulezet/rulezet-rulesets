rule TTP_XOR_MULT_DOSStub_4fb3 {
  strings:
    $key_4fb3 = { 1b db [2] 6f c3 [2] 28 c1 [2] 6f d0 [2] 21 dc [2] 2d d6 [2] 3a dd [2] 21 93 [2] 1c }

  condition:
    any of them
}