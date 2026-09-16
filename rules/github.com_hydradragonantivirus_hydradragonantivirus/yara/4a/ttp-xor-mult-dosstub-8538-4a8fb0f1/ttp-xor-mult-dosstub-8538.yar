rule TTP_XOR_MULT_DOSStub_8538 {
  strings:
    $key_8538 = { d1 50 [2] a5 48 [2] e2 4a [2] a5 5b [2] eb 57 [2] e7 5d [2] f0 56 [2] eb 18 [2] d6 }

  condition:
    any of them
}