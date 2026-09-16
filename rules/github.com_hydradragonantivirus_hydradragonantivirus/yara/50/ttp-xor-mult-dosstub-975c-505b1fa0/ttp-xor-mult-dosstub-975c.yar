rule TTP_XOR_MULT_DOSStub_975c {
  strings:
    $key_975c = { c3 34 [2] b7 2c [2] f0 2e [2] b7 3f [2] f9 33 [2] f5 39 [2] e2 32 [2] f9 7c [2] c4 }

  condition:
    any of them
}