rule TTP_XOR_MULT_DOSStub_8559 {
  strings:
    $key_8559 = { d1 31 [2] a5 29 [2] e2 2b [2] a5 3a [2] eb 36 [2] e7 3c [2] f0 37 [2] eb 79 [2] d6 }

  condition:
    any of them
}