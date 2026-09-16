rule TTP_XOR_MULT_DOSStub_a679 {
  strings:
    $key_a679 = { f2 11 [2] 86 09 [2] c1 0b [2] 86 1a [2] c8 16 [2] c4 1c [2] d3 17 [2] c8 59 [2] f5 }

  condition:
    any of them
}