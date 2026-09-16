rule TTP_XOR_MULT_DOSStub_865c {
  strings:
    $key_865c = { d2 34 [2] a6 2c [2] e1 2e [2] a6 3f [2] e8 33 [2] e4 39 [2] f3 32 [2] e8 7c [2] d5 }

  condition:
    any of them
}