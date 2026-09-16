rule TTP_XOR_MULT_DOSStub_9506 {
  strings:
    $key_9506 = { c1 6e [2] b5 76 [2] f2 74 [2] b5 65 [2] fb 69 [2] f7 63 [2] e0 68 [2] fb 26 [2] c6 }

  condition:
    any of them
}