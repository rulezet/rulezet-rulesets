rule TTP_XOR_MULT_DOSStub_92f6 {
  strings:
    $key_92f6 = { c6 9e [2] b2 86 [2] f5 84 [2] b2 95 [2] fc 99 [2] f0 93 [2] e7 98 [2] fc d6 [2] c1 }

  condition:
    any of them
}