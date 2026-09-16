rule TTP_XOR_MULT_DOSStub_963d {
  strings:
    $key_963d = { c2 55 [2] b6 4d [2] f1 4f [2] b6 5e [2] f8 52 [2] f4 58 [2] e3 53 [2] f8 1d [2] c5 }

  condition:
    any of them
}