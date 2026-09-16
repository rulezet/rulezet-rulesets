rule TTP_XOR_MULT_DOSStub_a14e {
  strings:
    $key_a14e = { f5 26 [2] 81 3e [2] c6 3c [2] 81 2d [2] cf 21 [2] c3 2b [2] d4 20 [2] cf 6e [2] f2 }

  condition:
    any of them
}