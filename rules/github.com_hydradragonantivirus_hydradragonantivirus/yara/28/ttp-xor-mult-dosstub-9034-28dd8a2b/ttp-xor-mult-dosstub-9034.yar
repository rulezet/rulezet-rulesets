rule TTP_XOR_MULT_DOSStub_9034 {
  strings:
    $key_9034 = { c4 5c [2] b0 44 [2] f7 46 [2] b0 57 [2] fe 5b [2] f2 51 [2] e5 5a [2] fe 14 [2] c3 }

  condition:
    any of them
}