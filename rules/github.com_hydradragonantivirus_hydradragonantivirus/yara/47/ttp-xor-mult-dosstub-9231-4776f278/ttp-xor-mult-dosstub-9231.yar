rule TTP_XOR_MULT_DOSStub_9231 {
  strings:
    $key_9231 = { c6 59 [2] b2 41 [2] f5 43 [2] b2 52 [2] fc 5e [2] f0 54 [2] e7 5f [2] fc 11 [2] c1 }

  condition:
    any of them
}