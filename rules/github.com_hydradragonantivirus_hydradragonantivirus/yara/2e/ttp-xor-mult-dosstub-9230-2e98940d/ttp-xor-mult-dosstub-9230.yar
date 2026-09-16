rule TTP_XOR_MULT_DOSStub_9230 {
  strings:
    $key_9230 = { c6 58 [2] b2 40 [2] f5 42 [2] b2 53 [2] fc 5f [2] f0 55 [2] e7 5e [2] fc 10 [2] c1 }

  condition:
    any of them
}