rule TTP_XOR_MULT_DOSStub_d6da {
  strings:
    $key_d6da = { 82 b2 [2] f6 aa [2] b1 a8 [2] f6 b9 [2] b8 b5 [2] b4 bf [2] a3 b4 [2] b8 fa [2] 85 }

  condition:
    any of them
}