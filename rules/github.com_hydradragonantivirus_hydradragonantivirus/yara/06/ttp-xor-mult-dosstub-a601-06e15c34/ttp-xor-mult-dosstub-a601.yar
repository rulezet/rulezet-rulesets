rule TTP_XOR_MULT_DOSStub_a601 {
  strings:
    $key_a601 = { f2 69 [2] 86 71 [2] c1 73 [2] 86 62 [2] c8 6e [2] c4 64 [2] d3 6f [2] c8 21 [2] f5 }

  condition:
    any of them
}