rule TTP_XOR_MULT_DOSStub_9704 {
  strings:
    $key_9704 = { c3 6c [2] b7 74 [2] f0 76 [2] b7 67 [2] f9 6b [2] f5 61 [2] e2 6a [2] f9 24 [2] c4 }

  condition:
    any of them
}