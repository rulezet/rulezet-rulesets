rule TTP_XOR_MULT_DOSStub_9733 {
  strings:
    $key_9733 = { c3 5b [2] b7 43 [2] f0 41 [2] b7 50 [2] f9 5c [2] f5 56 [2] e2 5d [2] f9 13 [2] c4 }

  condition:
    any of them
}