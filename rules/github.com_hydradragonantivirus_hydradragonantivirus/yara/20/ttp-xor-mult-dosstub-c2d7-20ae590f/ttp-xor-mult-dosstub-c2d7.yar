rule TTP_XOR_MULT_DOSStub_c2d7 {
  strings:
    $key_c2d7 = { 96 bf [2] e2 a7 [2] a5 a5 [2] e2 b4 [2] ac b8 [2] a0 b2 [2] b7 b9 [2] ac f7 [2] 91 }

  condition:
    any of them
}