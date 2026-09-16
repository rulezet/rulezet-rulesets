rule TTP_XOR_MULT_DOSStub_864b {
  strings:
    $key_864b = { d2 23 [2] a6 3b [2] e1 39 [2] a6 28 [2] e8 24 [2] e4 2e [2] f3 25 [2] e8 6b [2] d5 }

  condition:
    any of them
}