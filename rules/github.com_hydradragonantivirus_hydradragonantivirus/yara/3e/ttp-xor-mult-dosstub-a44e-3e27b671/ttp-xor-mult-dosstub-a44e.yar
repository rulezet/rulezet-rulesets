rule TTP_XOR_MULT_DOSStub_a44e {
  strings:
    $key_a44e = { f0 26 [2] 84 3e [2] c3 3c [2] 84 2d [2] ca 21 [2] c6 2b [2] d1 20 [2] ca 6e [2] f7 }

  condition:
    any of them
}