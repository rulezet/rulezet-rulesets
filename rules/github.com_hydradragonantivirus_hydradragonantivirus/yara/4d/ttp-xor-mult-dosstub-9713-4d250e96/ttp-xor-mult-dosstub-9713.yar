rule TTP_XOR_MULT_DOSStub_9713 {
  strings:
    $key_9713 = { c3 7b [2] b7 63 [2] f0 61 [2] b7 70 [2] f9 7c [2] f5 76 [2] e2 7d [2] f9 33 [2] c4 }

  condition:
    any of them
}