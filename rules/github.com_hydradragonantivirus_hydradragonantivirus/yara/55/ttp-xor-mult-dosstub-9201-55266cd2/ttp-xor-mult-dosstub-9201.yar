rule TTP_XOR_MULT_DOSStub_9201 {
  strings:
    $key_9201 = { c6 69 [2] b2 71 [2] f5 73 [2] b2 62 [2] fc 6e [2] f0 64 [2] e7 6f [2] fc 21 [2] c1 }

  condition:
    any of them
}