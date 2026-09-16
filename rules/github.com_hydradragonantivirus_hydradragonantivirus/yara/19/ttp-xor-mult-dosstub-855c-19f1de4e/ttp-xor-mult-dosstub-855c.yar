rule TTP_XOR_MULT_DOSStub_855c {
  strings:
    $key_855c = { d1 34 [2] a5 2c [2] e2 2e [2] a5 3f [2] eb 33 [2] e7 39 [2] f0 32 [2] eb 7c [2] d6 }

  condition:
    any of them
}