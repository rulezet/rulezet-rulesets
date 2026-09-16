rule TTP_XOR_MULT_DOSStub_85e4 {
  strings:
    $key_85e4 = { d1 8c [2] a5 94 [2] e2 96 [2] a5 87 [2] eb 8b [2] e7 81 [2] f0 8a [2] eb c4 [2] d6 }

  condition:
    any of them
}