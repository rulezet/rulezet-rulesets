rule TTP_XOR_MULT_DOSStub_9753 {
  strings:
    $key_9753 = { c3 3b [2] b7 23 [2] f0 21 [2] b7 30 [2] f9 3c [2] f5 36 [2] e2 3d [2] f9 73 [2] c4 }

  condition:
    any of them
}