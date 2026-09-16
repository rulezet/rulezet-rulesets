rule TTP_XOR_MULT_DOSStub_a617 {
  strings:
    $key_a617 = { f2 7f [2] 86 67 [2] c1 65 [2] 86 74 [2] c8 78 [2] c4 72 [2] d3 79 [2] c8 37 [2] f5 }

  condition:
    any of them
}