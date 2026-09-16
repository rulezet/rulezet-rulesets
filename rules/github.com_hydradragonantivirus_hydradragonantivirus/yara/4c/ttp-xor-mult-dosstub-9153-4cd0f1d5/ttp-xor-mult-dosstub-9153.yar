rule TTP_XOR_MULT_DOSStub_9153 {
  strings:
    $key_9153 = { c5 3b [2] b1 23 [2] f6 21 [2] b1 30 [2] ff 3c [2] f3 36 [2] e4 3d [2] ff 73 [2] c2 }

  condition:
    any of them
}