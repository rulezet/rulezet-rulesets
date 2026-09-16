rule TTP_XOR_MULT_DOSStub_9290 {
  strings:
    $key_9290 = { c6 f8 [2] b2 e0 [2] f5 e2 [2] b2 f3 [2] fc ff [2] f0 f5 [2] e7 fe [2] fc b0 [2] c1 }

  condition:
    any of them
}