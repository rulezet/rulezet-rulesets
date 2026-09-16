rule TTP_XOR_MULT_DOSStub_9228 {
  strings:
    $key_9228 = { c6 40 [2] b2 58 [2] f5 5a [2] b2 4b [2] fc 47 [2] f0 4d [2] e7 46 [2] fc 08 [2] c1 }

  condition:
    any of them
}