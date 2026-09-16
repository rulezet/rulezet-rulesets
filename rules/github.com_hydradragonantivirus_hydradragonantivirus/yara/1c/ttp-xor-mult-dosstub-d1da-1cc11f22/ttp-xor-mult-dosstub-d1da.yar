rule TTP_XOR_MULT_DOSStub_d1da {
  strings:
    $key_d1da = { 85 b2 [2] f1 aa [2] b6 a8 [2] f1 b9 [2] bf b5 [2] b3 bf [2] a4 b4 [2] bf fa [2] 82 }

  condition:
    any of them
}