rule TTP_XOR_MULT_DOSStub_ceaa {
  strings:
    $key_ceaa = { 9a c2 [2] ee da [2] a9 d8 [2] ee c9 [2] a0 c5 [2] ac cf [2] bb c4 [2] a0 8a [2] 9d }

  condition:
    any of them
}