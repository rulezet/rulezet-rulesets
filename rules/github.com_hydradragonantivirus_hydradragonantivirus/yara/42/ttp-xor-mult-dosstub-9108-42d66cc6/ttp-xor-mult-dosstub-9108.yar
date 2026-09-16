rule TTP_XOR_MULT_DOSStub_9108 {
  strings:
    $key_9108 = { c5 60 [2] b1 78 [2] f6 7a [2] b1 6b [2] ff 67 [2] f3 6d [2] e4 66 [2] ff 28 [2] c2 }

  condition:
    any of them
}