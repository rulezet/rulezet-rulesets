rule TTP_XOR_MULT_DOSStub_924b {
  strings:
    $key_924b = { c6 23 [2] b2 3b [2] f5 39 [2] b2 28 [2] fc 24 [2] f0 2e [2] e7 25 [2] fc 6b [2] c1 }

  condition:
    any of them
}