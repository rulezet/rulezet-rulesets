rule TTP_XOR_MULT_DOSStub_1fb3 {
  strings:
    $key_1fb3 = { 4b db [2] 3f c3 [2] 78 c1 [2] 3f d0 [2] 71 dc [2] 7d d6 [2] 6a dd [2] 71 93 [2] 4c }

  condition:
    any of them
}