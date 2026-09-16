rule TTP_XOR_MULT_DOSStub_9390 {
  strings:
    $key_9390 = { c7 f8 [2] b3 e0 [2] f4 e2 [2] b3 f3 [2] fd ff [2] f1 f5 [2] e6 fe [2] fd b0 [2] c0 }

  condition:
    any of them
}