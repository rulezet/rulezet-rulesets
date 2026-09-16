rule TTP_XOR_MULT_DOSStub_920c {
  strings:
    $key_920c = { c6 64 [2] b2 7c [2] f5 7e [2] b2 6f [2] fc 63 [2] f0 69 [2] e7 62 [2] fc 2c [2] c1 }

  condition:
    any of them
}