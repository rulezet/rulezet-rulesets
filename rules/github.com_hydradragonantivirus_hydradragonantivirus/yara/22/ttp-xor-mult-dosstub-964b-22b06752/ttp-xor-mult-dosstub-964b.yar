rule TTP_XOR_MULT_DOSStub_964b {
  strings:
    $key_964b = { c2 23 [2] b6 3b [2] f1 39 [2] b6 28 [2] f8 24 [2] f4 2e [2] e3 25 [2] f8 6b [2] c5 }

  condition:
    any of them
}