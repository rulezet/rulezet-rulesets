rule TTP_XOR_MULT_DOSStub_8509 {
  strings:
    $key_8509 = { d1 61 [2] a5 79 [2] e2 7b [2] a5 6a [2] eb 66 [2] e7 6c [2] f0 67 [2] eb 29 [2] d6 }

  condition:
    any of them
}