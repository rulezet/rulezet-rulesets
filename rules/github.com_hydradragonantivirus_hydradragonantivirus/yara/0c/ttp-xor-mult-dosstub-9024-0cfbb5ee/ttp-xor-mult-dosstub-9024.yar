rule TTP_XOR_MULT_DOSStub_9024 {
  strings:
    $key_9024 = { c4 4c [2] b0 54 [2] f7 56 [2] b0 47 [2] fe 4b [2] f2 41 [2] e5 4a [2] fe 04 [2] c3 }

  condition:
    any of them
}