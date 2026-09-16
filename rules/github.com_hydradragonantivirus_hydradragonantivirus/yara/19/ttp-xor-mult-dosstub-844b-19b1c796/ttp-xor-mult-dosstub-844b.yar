rule TTP_XOR_MULT_DOSStub_844b {
  strings:
    $key_844b = { d0 23 [2] a4 3b [2] e3 39 [2] a4 28 [2] ea 24 [2] e6 2e [2] f1 25 [2] ea 6b [2] d7 }

  condition:
    any of them
}