rule TTP_XOR_MULT_DOSStub_954e {
  strings:
    $key_954e = { c1 26 [2] b5 3e [2] f2 3c [2] b5 2d [2] fb 21 [2] f7 2b [2] e0 20 [2] fb 6e [2] c6 }

  condition:
    any of them
}