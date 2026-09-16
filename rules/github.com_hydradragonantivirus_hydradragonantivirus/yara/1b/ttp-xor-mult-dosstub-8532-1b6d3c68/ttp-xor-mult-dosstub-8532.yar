rule TTP_XOR_MULT_DOSStub_8532 {
  strings:
    $key_8532 = { d1 5a [2] a5 42 [2] e2 40 [2] a5 51 [2] eb 5d [2] e7 57 [2] f0 5c [2] eb 12 [2] d6 }

  condition:
    any of them
}