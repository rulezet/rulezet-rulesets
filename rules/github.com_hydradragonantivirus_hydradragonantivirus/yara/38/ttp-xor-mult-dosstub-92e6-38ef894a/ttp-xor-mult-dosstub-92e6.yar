rule TTP_XOR_MULT_DOSStub_92e6 {
  strings:
    $key_92e6 = { c6 8e [2] b2 96 [2] f5 94 [2] b2 85 [2] fc 89 [2] f0 83 [2] e7 88 [2] fc c6 [2] c1 }

  condition:
    any of them
}