rule TTP_XOR_MULT_DOSStub_9633 {
  strings:
    $key_9633 = { c2 5b [2] b6 43 [2] f1 41 [2] b6 50 [2] f8 5c [2] f4 56 [2] e3 5d [2] f8 13 [2] c5 }

  condition:
    any of them
}