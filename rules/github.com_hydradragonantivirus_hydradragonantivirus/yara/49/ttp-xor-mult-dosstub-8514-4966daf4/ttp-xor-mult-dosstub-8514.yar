rule TTP_XOR_MULT_DOSStub_8514 {
  strings:
    $key_8514 = { d1 7c [2] a5 64 [2] e2 66 [2] a5 77 [2] eb 7b [2] e7 71 [2] f0 7a [2] eb 34 [2] d6 }

  condition:
    any of them
}