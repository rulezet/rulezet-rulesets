rule TTP_XOR_MULT_DOSStub_955d {
  strings:
    $key_955d = { c1 35 [2] b5 2d [2] f2 2f [2] b5 3e [2] fb 32 [2] f7 38 [2] e0 33 [2] fb 7d [2] c6 }

  condition:
    any of them
}