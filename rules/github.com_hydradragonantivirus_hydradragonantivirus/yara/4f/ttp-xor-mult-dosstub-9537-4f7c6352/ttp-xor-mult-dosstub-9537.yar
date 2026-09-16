rule TTP_XOR_MULT_DOSStub_9537 {
  strings:
    $key_9537 = { c1 5f [2] b5 47 [2] f2 45 [2] b5 54 [2] fb 58 [2] f7 52 [2] e0 59 [2] fb 17 [2] c6 }

  condition:
    any of them
}