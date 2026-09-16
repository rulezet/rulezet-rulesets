rule TTP_XOR_MULT_DOSStub_9152 {
  strings:
    $key_9152 = { c5 3a [2] b1 22 [2] f6 20 [2] b1 31 [2] ff 3d [2] f3 37 [2] e4 3c [2] ff 72 [2] c2 }

  condition:
    any of them
}