rule TTP_XOR_MULT_DOSStub_c0d1 {
  strings:
    $key_c0d1 = { 94 b9 [2] e0 a1 [2] a7 a3 [2] e0 b2 [2] ae be [2] a2 b4 [2] b5 bf [2] ae f1 [2] 93 }

  condition:
    any of them
}