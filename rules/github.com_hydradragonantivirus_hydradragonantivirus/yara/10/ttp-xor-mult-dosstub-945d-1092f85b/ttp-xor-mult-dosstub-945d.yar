rule TTP_XOR_MULT_DOSStub_945d {
  strings:
    $key_945d = { c0 35 [2] b4 2d [2] f3 2f [2] b4 3e [2] fa 32 [2] f6 38 [2] e1 33 [2] fa 7d [2] c7 }

  condition:
    any of them
}