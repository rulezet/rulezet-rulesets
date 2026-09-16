rule TTP_XOR_MULT_DOSStub_a64e {
  strings:
    $key_a64e = { f2 26 [2] 86 3e [2] c1 3c [2] 86 2d [2] c8 21 [2] c4 2b [2] d3 20 [2] c8 6e [2] f5 }

  condition:
    any of them
}