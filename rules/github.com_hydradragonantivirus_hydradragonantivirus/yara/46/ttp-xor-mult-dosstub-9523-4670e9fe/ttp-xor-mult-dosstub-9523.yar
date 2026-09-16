rule TTP_XOR_MULT_DOSStub_9523 {
  strings:
    $key_9523 = { c1 4b [2] b5 53 [2] f2 51 [2] b5 40 [2] fb 4c [2] f7 46 [2] e0 4d [2] fb 03 [2] c6 }

  condition:
    any of them
}