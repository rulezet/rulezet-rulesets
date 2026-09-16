rule TTP_XOR_MULT_DOSStub_945f {
  strings:
    $key_945f = { c0 37 [2] b4 2f [2] f3 2d [2] b4 3c [2] fa 30 [2] f6 3a [2] e1 31 [2] fa 7f [2] c7 }

  condition:
    any of them
}