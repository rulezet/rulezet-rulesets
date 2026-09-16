rule TTP_XOR_MULT_DOSStub_9534 {
  strings:
    $key_9534 = { c1 5c [2] b5 44 [2] f2 46 [2] b5 57 [2] fb 5b [2] f7 51 [2] e0 5a [2] fb 14 [2] c6 }

  condition:
    any of them
}