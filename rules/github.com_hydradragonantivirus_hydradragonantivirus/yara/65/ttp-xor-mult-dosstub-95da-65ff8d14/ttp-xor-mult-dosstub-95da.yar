rule TTP_XOR_MULT_DOSStub_95da {
  strings:
    $key_95da = { c1 b2 [2] b5 aa [2] f2 a8 [2] b5 b9 [2] fb b5 [2] f7 bf [2] e0 b4 [2] fb fa [2] c6 }

  condition:
    any of them
}