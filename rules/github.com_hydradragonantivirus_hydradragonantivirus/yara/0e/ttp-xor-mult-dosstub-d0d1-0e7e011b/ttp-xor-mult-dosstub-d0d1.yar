rule TTP_XOR_MULT_DOSStub_d0d1 {
  strings:
    $key_d0d1 = { 84 b9 [2] f0 a1 [2] b7 a3 [2] f0 b2 [2] be be [2] b2 b4 [2] a5 bf [2] be f1 [2] 83 }

  condition:
    any of them
}