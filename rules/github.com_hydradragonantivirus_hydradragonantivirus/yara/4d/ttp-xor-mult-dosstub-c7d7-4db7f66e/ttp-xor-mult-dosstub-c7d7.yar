rule TTP_XOR_MULT_DOSStub_c7d7 {
  strings:
    $key_c7d7 = { 93 bf [2] e7 a7 [2] a0 a5 [2] e7 b4 [2] a9 b8 [2] a5 b2 [2] b2 b9 [2] a9 f7 [2] 94 }

  condition:
    any of them
}