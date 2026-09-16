rule TTP_XOR_MULT_DOSStub_9550 {
  strings:
    $key_9550 = { c1 38 [2] b5 20 [2] f2 22 [2] b5 33 [2] fb 3f [2] f7 35 [2] e0 3e [2] fb 70 [2] c6 }

  condition:
    any of them
}