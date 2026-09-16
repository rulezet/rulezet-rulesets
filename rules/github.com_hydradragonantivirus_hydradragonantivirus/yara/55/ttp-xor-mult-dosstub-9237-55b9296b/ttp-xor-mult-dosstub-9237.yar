rule TTP_XOR_MULT_DOSStub_9237 {
  strings:
    $key_9237 = { c6 5f [2] b2 47 [2] f5 45 [2] b2 54 [2] fc 58 [2] f0 52 [2] e7 59 [2] fc 17 [2] c1 }

  condition:
    any of them
}