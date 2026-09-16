rule TTP_XOR_MULT_DOSStub_9528 {
  strings:
    $key_9528 = { c1 40 [2] b5 58 [2] f2 5a [2] b5 4b [2] fb 47 [2] f7 4d [2] e0 46 [2] fb 08 [2] c6 }

  condition:
    any of them
}