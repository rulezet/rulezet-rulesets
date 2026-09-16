rule TTP_XOR_MULT_DOSStub_9510 {
  strings:
    $key_9510 = { c1 78 [2] b5 60 [2] f2 62 [2] b5 73 [2] fb 7f [2] f7 75 [2] e0 7e [2] fb 30 [2] c6 }

  condition:
    any of them
}