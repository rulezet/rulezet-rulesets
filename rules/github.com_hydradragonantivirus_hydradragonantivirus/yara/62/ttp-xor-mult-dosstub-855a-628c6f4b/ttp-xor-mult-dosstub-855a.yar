rule TTP_XOR_MULT_DOSStub_855a {
  strings:
    $key_855a = { d1 32 [2] a5 2a [2] e2 28 [2] a5 39 [2] eb 35 [2] e7 3f [2] f0 34 [2] eb 7a [2] d6 }

  condition:
    any of them
}