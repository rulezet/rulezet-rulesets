rule TTP_XOR_MULT_DOSStub_9513 {
  strings:
    $key_9513 = { c1 7b [2] b5 63 [2] f2 61 [2] b5 70 [2] fb 7c [2] f7 76 [2] e0 7d [2] fb 33 [2] c6 }

  condition:
    any of them
}