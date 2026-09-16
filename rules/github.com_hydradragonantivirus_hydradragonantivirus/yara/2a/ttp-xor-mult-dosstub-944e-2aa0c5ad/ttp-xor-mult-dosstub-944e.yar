rule TTP_XOR_MULT_DOSStub_944e {
  strings:
    $key_944e = { c0 26 [2] b4 3e [2] f3 3c [2] b4 2d [2] fa 21 [2] f6 2b [2] e1 20 [2] fa 6e [2] c7 }

  condition:
    any of them
}