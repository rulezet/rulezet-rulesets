rule TTP_XOR_MULT_DOSStub_0195 {
  strings:
    $key_0195 = { 55 fd [2] 21 e5 [2] 66 e7 [2] 21 f6 [2] 6f fa [2] 63 f0 [2] 74 fb [2] 6f b5 [2] 52 }

  condition:
    any of them
}