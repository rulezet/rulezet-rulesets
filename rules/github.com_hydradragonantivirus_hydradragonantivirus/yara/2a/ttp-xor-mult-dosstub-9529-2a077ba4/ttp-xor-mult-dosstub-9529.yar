rule TTP_XOR_MULT_DOSStub_9529 {
  strings:
    $key_9529 = { c1 41 [2] b5 59 [2] f2 5b [2] b5 4a [2] fb 46 [2] f7 4c [2] e0 47 [2] fb 09 [2] c6 }

  condition:
    any of them
}