rule TTP_XOR_MULT_DOSStub_91da {
  strings:
    $key_91da = { c5 b2 [2] b1 aa [2] f6 a8 [2] b1 b9 [2] ff b5 [2] f3 bf [2] e4 b4 [2] ff fa [2] c2 }

  condition:
    any of them
}