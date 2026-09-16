rule TTP_XOR_MULT_DOSStub_8556 {
  strings:
    $key_8556 = { d1 3e [2] a5 26 [2] e2 24 [2] a5 35 [2] eb 39 [2] e7 33 [2] f0 38 [2] eb 76 [2] d6 }

  condition:
    any of them
}