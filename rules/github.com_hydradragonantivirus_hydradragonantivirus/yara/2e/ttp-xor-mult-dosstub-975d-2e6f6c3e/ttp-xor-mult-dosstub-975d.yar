rule TTP_XOR_MULT_DOSStub_975d {
  strings:
    $key_975d = { c3 35 [2] b7 2d [2] f0 2f [2] b7 3e [2] f9 32 [2] f5 38 [2] e2 33 [2] f9 7d [2] c4 }

  condition:
    any of them
}