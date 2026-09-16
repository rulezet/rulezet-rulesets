rule TTP_XOR_MULT_DOSStub_9178 {
  strings:
    $key_9178 = { c5 10 [2] b1 08 [2] f6 0a [2] b1 1b [2] ff 17 [2] f3 1d [2] e4 16 [2] ff 58 [2] c2 }

  condition:
    any of them
}