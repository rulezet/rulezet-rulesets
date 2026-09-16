rule TTP_XOR_MULT_DOSStub_9556 {
  strings:
    $key_9556 = { c1 3e [2] b5 26 [2] f2 24 [2] b5 35 [2] fb 39 [2] f7 33 [2] e0 38 [2] fb 76 [2] c6 }

  condition:
    any of them
}