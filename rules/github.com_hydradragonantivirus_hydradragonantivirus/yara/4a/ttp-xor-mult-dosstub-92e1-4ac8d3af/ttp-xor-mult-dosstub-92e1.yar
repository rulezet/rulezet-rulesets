rule TTP_XOR_MULT_DOSStub_92e1 {
  strings:
    $key_92e1 = { c6 89 [2] b2 91 [2] f5 93 [2] b2 82 [2] fc 8e [2] f0 84 [2] e7 8f [2] fc c1 [2] c1 }

  condition:
    any of them
}