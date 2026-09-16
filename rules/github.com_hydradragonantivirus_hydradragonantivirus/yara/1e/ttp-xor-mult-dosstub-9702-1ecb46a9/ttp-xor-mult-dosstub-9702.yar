rule TTP_XOR_MULT_DOSStub_9702 {
  strings:
    $key_9702 = { c3 6a [2] b7 72 [2] f0 70 [2] b7 61 [2] f9 6d [2] f5 67 [2] e2 6c [2] f9 22 [2] c4 }

  condition:
    any of them
}