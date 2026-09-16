rule TTP_XOR_MULT_DOSStub_a65d {
  strings:
    $key_a65d = { f2 35 [2] 86 2d [2] c1 2f [2] 86 3e [2] c8 32 [2] c4 38 [2] d3 33 [2] c8 7d [2] f5 }

  condition:
    any of them
}