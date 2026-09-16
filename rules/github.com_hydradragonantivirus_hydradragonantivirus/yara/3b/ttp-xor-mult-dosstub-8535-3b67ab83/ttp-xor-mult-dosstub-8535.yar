rule TTP_XOR_MULT_DOSStub_8535 {
  strings:
    $key_8535 = { d1 5d [2] a5 45 [2] e2 47 [2] a5 56 [2] eb 5a [2] e7 50 [2] f0 5b [2] eb 15 [2] d6 }

  condition:
    any of them
}