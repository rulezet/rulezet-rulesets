rule TTP_XOR_MULT_DOSStub_a672 {
  strings:
    $key_a672 = { f2 1a [2] 86 02 [2] c1 00 [2] 86 11 [2] c8 1d [2] c4 17 [2] d3 1c [2] c8 52 [2] f5 }

  condition:
    any of them
}