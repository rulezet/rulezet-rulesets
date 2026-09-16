rule TTP_XOR_MULT_DOSStub_9115 {
  strings:
    $key_9115 = { c5 7d [2] b1 65 [2] f6 67 [2] b1 76 [2] ff 7a [2] f3 70 [2] e4 7b [2] ff 35 [2] c2 }

  condition:
    any of them
}