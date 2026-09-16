rule TTP_XOR_MULT_DOSStub_9165 {
  strings:
    $key_9165 = { c5 0d [2] b1 15 [2] f6 17 [2] b1 06 [2] ff 0a [2] f3 00 [2] e4 0b [2] ff 45 [2] c2 }

  condition:
    any of them
}