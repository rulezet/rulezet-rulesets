rule TTP_XOR_MULT_DOSStub_9504 {
  strings:
    $key_9504 = { c1 6c [2] b5 74 [2] f2 76 [2] b5 67 [2] fb 6b [2] f7 61 [2] e0 6a [2] fb 24 [2] c6 }

  condition:
    any of them
}