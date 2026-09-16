rule TTP_XOR_MULT_DOSStub_9149 {
  strings:
    $key_9149 = { c5 21 [2] b1 39 [2] f6 3b [2] b1 2a [2] ff 26 [2] f3 2c [2] e4 27 [2] ff 69 [2] c2 }

  condition:
    any of them
}