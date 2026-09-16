rule TTP_XOR_MULT_DOSStub_d7d7 {
  strings:
    $key_d7d7 = { 83 bf [2] f7 a7 [2] b0 a5 [2] f7 b4 [2] b9 b8 [2] b5 b2 [2] a2 b9 [2] b9 f7 [2] 84 }

  condition:
    any of them
}