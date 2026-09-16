rule TTP_XOR_MULT_DOSStub_a2da {
  strings:
    $key_a2da = { f6 b2 [2] 82 aa [2] c5 a8 [2] 82 b9 [2] cc b5 [2] c0 bf [2] d7 b4 [2] cc fa [2] f1 }

  condition:
    any of them
}