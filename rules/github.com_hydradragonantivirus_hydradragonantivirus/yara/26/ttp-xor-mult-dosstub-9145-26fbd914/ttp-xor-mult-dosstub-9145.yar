rule TTP_XOR_MULT_DOSStub_9145 {
  strings:
    $key_9145 = { c5 2d [2] b1 35 [2] f6 37 [2] b1 26 [2] ff 2a [2] f3 20 [2] e4 2b [2] ff 65 [2] c2 }

  condition:
    any of them
}