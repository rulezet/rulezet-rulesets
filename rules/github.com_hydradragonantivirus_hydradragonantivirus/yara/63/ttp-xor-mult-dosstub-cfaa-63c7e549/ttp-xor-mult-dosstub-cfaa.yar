rule TTP_XOR_MULT_DOSStub_cfaa {
  strings:
    $key_cfaa = { 9b c2 [2] ef da [2] a8 d8 [2] ef c9 [2] a1 c5 [2] ad cf [2] ba c4 [2] a1 8a [2] 9c }

  condition:
    any of them
}