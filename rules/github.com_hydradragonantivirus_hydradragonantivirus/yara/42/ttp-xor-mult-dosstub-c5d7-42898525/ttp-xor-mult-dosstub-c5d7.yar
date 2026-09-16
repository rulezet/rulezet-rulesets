rule TTP_XOR_MULT_DOSStub_c5d7 {
  strings:
    $key_c5d7 = { 91 bf [2] e5 a7 [2] a2 a5 [2] e5 b4 [2] ab b8 [2] a7 b2 [2] b0 b9 [2] ab f7 [2] 96 }

  condition:
    any of them
}