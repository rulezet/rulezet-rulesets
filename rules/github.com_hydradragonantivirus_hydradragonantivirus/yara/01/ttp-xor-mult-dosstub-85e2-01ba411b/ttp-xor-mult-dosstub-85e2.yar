rule TTP_XOR_MULT_DOSStub_85e2 {
  strings:
    $key_85e2 = { d1 8a [2] a5 92 [2] e2 90 [2] a5 81 [2] eb 8d [2] e7 87 [2] f0 8c [2] eb c2 [2] d6 }

  condition:
    any of them
}