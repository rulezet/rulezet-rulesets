rule TTP_XOR_MULT_DOSStub_8557 {
  strings:
    $key_8557 = { d1 3f [2] a5 27 [2] e2 25 [2] a5 34 [2] eb 38 [2] e7 32 [2] f0 39 [2] eb 77 [2] d6 }

  condition:
    any of them
}