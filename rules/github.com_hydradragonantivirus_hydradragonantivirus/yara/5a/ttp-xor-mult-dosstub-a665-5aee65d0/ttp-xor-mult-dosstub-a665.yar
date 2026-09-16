rule TTP_XOR_MULT_DOSStub_a665 {
  strings:
    $key_a665 = { f2 0d [2] 86 15 [2] c1 17 [2] 86 06 [2] c8 0a [2] c4 00 [2] d3 0b [2] c8 45 [2] f5 }

  condition:
    any of them
}