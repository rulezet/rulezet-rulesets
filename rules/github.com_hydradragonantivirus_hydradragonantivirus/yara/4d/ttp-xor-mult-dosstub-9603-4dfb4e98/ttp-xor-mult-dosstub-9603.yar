rule TTP_XOR_MULT_DOSStub_9603 {
  strings:
    $key_9603 = { c2 6b [2] b6 73 [2] f1 71 [2] b6 60 [2] f8 6c [2] f4 66 [2] e3 6d [2] f8 23 [2] c5 }

  condition:
    any of them
}