rule TTP_XOR_MULT_DOSStub_9207 {
  strings:
    $key_9207 = { c6 6f [2] b2 77 [2] f5 75 [2] b2 64 [2] fc 68 [2] f0 62 [2] e7 69 [2] fc 27 [2] c1 }

  condition:
    any of them
}