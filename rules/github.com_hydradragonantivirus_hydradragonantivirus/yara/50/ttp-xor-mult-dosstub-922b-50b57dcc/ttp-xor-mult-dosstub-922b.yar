rule TTP_XOR_MULT_DOSStub_922b {
  strings:
    $key_922b = { c6 43 [2] b2 5b [2] f5 59 [2] b2 48 [2] fc 44 [2] f0 4e [2] e7 45 [2] fc 0b [2] c1 }

  condition:
    any of them
}