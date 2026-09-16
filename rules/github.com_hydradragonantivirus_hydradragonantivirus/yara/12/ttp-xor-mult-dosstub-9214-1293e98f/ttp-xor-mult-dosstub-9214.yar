rule TTP_XOR_MULT_DOSStub_9214 {
  strings:
    $key_9214 = { c6 7c [2] b2 64 [2] f5 66 [2] b2 77 [2] fc 7b [2] f0 71 [2] e7 7a [2] fc 34 [2] c1 }

  condition:
    any of them
}