rule TTP_XOR_MULT_DOSStub_3195 {
  strings:
    $key_3195 = { 65 fd [2] 11 e5 [2] 56 e7 [2] 11 f6 [2] 5f fa [2] 53 f0 [2] 44 fb [2] 5f b5 [2] 62 }

  condition:
    any of them
}