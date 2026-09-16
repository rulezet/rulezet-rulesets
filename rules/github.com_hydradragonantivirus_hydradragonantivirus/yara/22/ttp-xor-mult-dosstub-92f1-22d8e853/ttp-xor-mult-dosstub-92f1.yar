rule TTP_XOR_MULT_DOSStub_92f1 {
  strings:
    $key_92f1 = { c6 99 [2] b2 81 [2] f5 83 [2] b2 92 [2] fc 9e [2] f0 94 [2] e7 9f [2] fc d1 [2] c1 }

  condition:
    any of them
}