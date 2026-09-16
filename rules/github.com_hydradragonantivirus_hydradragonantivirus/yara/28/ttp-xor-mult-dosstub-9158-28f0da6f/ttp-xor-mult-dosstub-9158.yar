rule TTP_XOR_MULT_DOSStub_9158 {
  strings:
    $key_9158 = { c5 30 [2] b1 28 [2] f6 2a [2] b1 3b [2] ff 37 [2] f3 3d [2] e4 36 [2] ff 78 [2] c2 }

  condition:
    any of them
}