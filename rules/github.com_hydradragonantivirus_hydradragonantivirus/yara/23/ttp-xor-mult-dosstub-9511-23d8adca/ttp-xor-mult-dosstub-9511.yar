rule TTP_XOR_MULT_DOSStub_9511 {
  strings:
    $key_9511 = { c1 79 [2] b5 61 [2] f2 63 [2] b5 72 [2] fb 7e [2] f7 74 [2] e0 7f [2] fb 31 [2] c6 }

  condition:
    any of them
}