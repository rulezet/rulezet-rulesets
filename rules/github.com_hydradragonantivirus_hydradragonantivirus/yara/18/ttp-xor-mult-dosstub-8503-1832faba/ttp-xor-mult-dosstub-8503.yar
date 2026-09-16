rule TTP_XOR_MULT_DOSStub_8503 {
  strings:
    $key_8503 = { d1 6b [2] a5 73 [2] e2 71 [2] a5 60 [2] eb 6c [2] e7 66 [2] f0 6d [2] eb 23 [2] d6 }

  condition:
    any of them
}