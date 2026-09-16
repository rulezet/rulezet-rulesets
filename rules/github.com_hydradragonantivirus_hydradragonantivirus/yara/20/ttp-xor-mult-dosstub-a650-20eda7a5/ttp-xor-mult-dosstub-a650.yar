rule TTP_XOR_MULT_DOSStub_a650 {
  strings:
    $key_a650 = { f2 38 [2] 86 20 [2] c1 22 [2] 86 33 [2] c8 3f [2] c4 35 [2] d3 3e [2] c8 70 [2] f5 }

  condition:
    any of them
}