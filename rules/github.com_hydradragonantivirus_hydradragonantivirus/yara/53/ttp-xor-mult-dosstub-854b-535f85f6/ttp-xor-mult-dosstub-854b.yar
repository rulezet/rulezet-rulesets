rule TTP_XOR_MULT_DOSStub_854b {
  strings:
    $key_854b = { d1 23 [2] a5 3b [2] e2 39 [2] a5 28 [2] eb 24 [2] e7 2e [2] f0 25 [2] eb 6b [2] d6 }

  condition:
    any of them
}