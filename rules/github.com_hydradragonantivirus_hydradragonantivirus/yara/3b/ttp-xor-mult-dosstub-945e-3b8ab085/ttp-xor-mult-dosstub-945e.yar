rule TTP_XOR_MULT_DOSStub_945e {
  strings:
    $key_945e = { c0 36 [2] b4 2e [2] f3 2c [2] b4 3d [2] fa 31 [2] f6 3b [2] e1 30 [2] fa 7e [2] c7 }

  condition:
    any of them
}