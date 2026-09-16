rule TTP_XOR_MULT_DOSStub_965e {
  strings:
    $key_965e = { c2 36 [2] b6 2e [2] f1 2c [2] b6 3d [2] f8 31 [2] f4 3b [2] e3 30 [2] f8 7e [2] c5 }

  condition:
    any of them
}