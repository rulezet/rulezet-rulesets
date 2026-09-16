rule TTP_XOR_MULT_DOSStub_9233 {
  strings:
    $key_9233 = { c6 5b [2] b2 43 [2] f5 41 [2] b2 50 [2] fc 5c [2] f0 56 [2] e7 5d [2] fc 13 [2] c1 }

  condition:
    any of them
}