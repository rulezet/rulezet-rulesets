rule TTP_XOR_MULT_DOSStub_80da {
  strings:
    $key_80da = { d4 b2 [2] a0 aa [2] e7 a8 [2] a0 b9 [2] ee b5 [2] e2 bf [2] f5 b4 [2] ee fa [2] d3 }

  condition:
    any of them
}