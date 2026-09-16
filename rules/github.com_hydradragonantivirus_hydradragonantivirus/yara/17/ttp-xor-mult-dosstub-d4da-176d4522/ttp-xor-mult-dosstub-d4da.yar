rule TTP_XOR_MULT_DOSStub_d4da {
  strings:
    $key_d4da = { 80 b2 [2] f4 aa [2] b3 a8 [2] f4 b9 [2] ba b5 [2] b6 bf [2] a1 b4 [2] ba fa [2] 87 }

  condition:
    any of them
}