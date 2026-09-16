rule TTP_XOR_MULT_DOSStub_a4da {
  strings:
    $key_a4da = { f0 b2 [2] 84 aa [2] c3 a8 [2] 84 b9 [2] ca b5 [2] c6 bf [2] d1 b4 [2] ca fa [2] f7 }

  condition:
    any of them
}