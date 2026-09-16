rule TTP_XOR_MULT_DOSStub_9053 {
  strings:
    $key_9053 = { c4 3b [2] b0 23 [2] f7 21 [2] b0 30 [2] fe 3c [2] f2 36 [2] e5 3d [2] fe 73 [2] c3 }

  condition:
    any of them
}