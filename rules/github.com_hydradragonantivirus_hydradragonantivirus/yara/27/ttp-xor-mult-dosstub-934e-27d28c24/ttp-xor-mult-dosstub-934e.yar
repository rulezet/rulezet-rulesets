rule TTP_XOR_MULT_DOSStub_934e {
  strings:
    $key_934e = { c7 26 [2] b3 3e [2] f4 3c [2] b3 2d [2] fd 21 [2] f1 2b [2] e6 20 [2] fd 6e [2] c0 }

  condition:
    any of them
}