rule TTP_XOR_MULT_DOSStub_9551 {
  strings:
    $key_9551 = { c1 39 [2] b5 21 [2] f2 23 [2] b5 32 [2] fb 3e [2] f7 34 [2] e0 3f [2] fb 71 [2] c6 }

  condition:
    any of them
}