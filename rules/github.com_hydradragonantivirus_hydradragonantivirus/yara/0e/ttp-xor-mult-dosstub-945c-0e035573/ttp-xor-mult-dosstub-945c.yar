rule TTP_XOR_MULT_DOSStub_945c {
  strings:
    $key_945c = { c0 34 [2] b4 2c [2] f3 2e [2] b4 3f [2] fa 33 [2] f6 39 [2] e1 32 [2] fa 7c [2] c7 }

  condition:
    any of them
}