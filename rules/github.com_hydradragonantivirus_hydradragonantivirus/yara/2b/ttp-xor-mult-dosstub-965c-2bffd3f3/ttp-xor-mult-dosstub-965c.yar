rule TTP_XOR_MULT_DOSStub_965c {
  strings:
    $key_965c = { c2 34 [2] b6 2c [2] f1 2e [2] b6 3f [2] f8 33 [2] f4 39 [2] e3 32 [2] f8 7c [2] c5 }

  condition:
    any of them
}