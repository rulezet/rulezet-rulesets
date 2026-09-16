rule TTP_XOR_MULT_DOSStub_9134 {
  strings:
    $key_9134 = { c5 5c [2] b1 44 [2] f6 46 [2] b1 57 [2] ff 5b [2] f3 51 [2] e4 5a [2] ff 14 [2] c2 }

  condition:
    any of them
}