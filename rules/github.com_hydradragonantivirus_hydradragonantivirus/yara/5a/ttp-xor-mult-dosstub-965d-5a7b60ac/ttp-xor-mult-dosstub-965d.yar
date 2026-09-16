rule TTP_XOR_MULT_DOSStub_965d {
  strings:
    $key_965d = { c2 35 [2] b6 2d [2] f1 2f [2] b6 3e [2] f8 32 [2] f4 38 [2] e3 33 [2] f8 7d [2] c5 }

  condition:
    any of them
}