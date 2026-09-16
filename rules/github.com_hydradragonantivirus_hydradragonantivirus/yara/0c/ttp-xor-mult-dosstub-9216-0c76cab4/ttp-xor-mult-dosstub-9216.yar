rule TTP_XOR_MULT_DOSStub_9216 {
  strings:
    $key_9216 = { c6 7e [2] b2 66 [2] f5 64 [2] b2 75 [2] fc 79 [2] f0 73 [2] e7 78 [2] fc 36 [2] c1 }

  condition:
    any of them
}