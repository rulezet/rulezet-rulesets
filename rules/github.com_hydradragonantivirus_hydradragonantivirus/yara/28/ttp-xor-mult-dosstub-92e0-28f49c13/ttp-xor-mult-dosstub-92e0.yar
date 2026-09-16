rule TTP_XOR_MULT_DOSStub_92e0 {
  strings:
    $key_92e0 = { c6 88 [2] b2 90 [2] f5 92 [2] b2 83 [2] fc 8f [2] f0 85 [2] e7 8e [2] fc c0 [2] c1 }

  condition:
    any of them
}