rule TTP_XOR_MULT_DOSStub_9571 {
  strings:
    $key_9571 = { c1 19 [2] b5 01 [2] f2 03 [2] b5 12 [2] fb 1e [2] f7 14 [2] e0 1f [2] fb 51 [2] c6 }

  condition:
    any of them
}