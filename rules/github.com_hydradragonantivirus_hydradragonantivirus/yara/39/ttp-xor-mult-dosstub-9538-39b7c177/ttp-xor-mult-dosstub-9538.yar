rule TTP_XOR_MULT_DOSStub_9538 {
  strings:
    $key_9538 = { c1 50 [2] b5 48 [2] f2 4a [2] b5 5b [2] fb 57 [2] f7 5d [2] e0 56 [2] fb 18 [2] c6 }

  condition:
    any of them
}