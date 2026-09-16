rule TTP_XOR_MULT_DOSStub_854e {
  strings:
    $key_854e = { d1 26 [2] a5 3e [2] e2 3c [2] a5 2d [2] eb 21 [2] e7 2b [2] f0 20 [2] eb 6e [2] d6 }

  condition:
    any of them
}