rule TTP_XOR_MULT_DOSStub_9039 {
  strings:
    $key_9039 = { c4 51 [2] b0 49 [2] f7 4b [2] b0 5a [2] fe 56 [2] f2 5c [2] e5 57 [2] fe 19 [2] c3 }

  condition:
    any of them
}