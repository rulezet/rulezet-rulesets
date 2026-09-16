rule TTP_XOR_MULT_DOSStub_a673 {
  strings:
    $key_a673 = { f2 1b [2] 86 03 [2] c1 01 [2] 86 10 [2] c8 1c [2] c4 16 [2] d3 1d [2] c8 53 [2] f5 }

  condition:
    any of them
}