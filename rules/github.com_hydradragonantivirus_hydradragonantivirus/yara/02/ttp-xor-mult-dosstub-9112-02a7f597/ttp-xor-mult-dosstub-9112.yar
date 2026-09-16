rule TTP_XOR_MULT_DOSStub_9112 {
  strings:
    $key_9112 = { c5 7a [2] b1 62 [2] f6 60 [2] b1 71 [2] ff 7d [2] f3 77 [2] e4 7c [2] ff 32 [2] c2 }

  condition:
    any of them
}