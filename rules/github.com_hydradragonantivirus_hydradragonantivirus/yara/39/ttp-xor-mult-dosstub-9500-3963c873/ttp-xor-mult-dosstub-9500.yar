rule TTP_XOR_MULT_DOSStub_9500 {
  strings:
    $key_9500 = { c1 68 [2] b5 70 [2] f2 72 [2] b5 63 [2] fb 6f [2] f7 65 [2] e0 6e [2] fb 20 [2] c6 }

  condition:
    any of them
}