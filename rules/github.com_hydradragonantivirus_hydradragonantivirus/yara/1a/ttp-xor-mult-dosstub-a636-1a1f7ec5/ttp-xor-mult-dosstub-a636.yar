rule TTP_XOR_MULT_DOSStub_a636 {
  strings:
    $key_a636 = { f2 5e [2] 86 46 [2] c1 44 [2] 86 55 [2] c8 59 [2] c4 53 [2] d3 58 [2] c8 16 [2] f5 }

  condition:
    any of them
}