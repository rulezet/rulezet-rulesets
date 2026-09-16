rule TTP_XOR_MULT_DOSStub_9235 {
  strings:
    $key_9235 = { c6 5d [2] b2 45 [2] f5 47 [2] b2 56 [2] fc 5a [2] f0 50 [2] e7 5b [2] fc 15 [2] c1 }

  condition:
    any of them
}