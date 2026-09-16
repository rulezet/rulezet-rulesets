rule TTP_XOR_MULT_DOSStub_9612 {
  strings:
    $key_9612 = { c2 7a [2] b6 62 [2] f1 60 [2] b6 71 [2] f8 7d [2] f4 77 [2] e3 7c [2] f8 32 [2] c5 }

  condition:
    any of them
}