rule TTP_XOR_MULT_DOSStub_9616 {
  strings:
    $key_9616 = { c2 7e [2] b6 66 [2] f1 64 [2] b6 75 [2] f8 79 [2] f4 73 [2] e3 78 [2] f8 36 [2] c5 }

  condition:
    any of them
}