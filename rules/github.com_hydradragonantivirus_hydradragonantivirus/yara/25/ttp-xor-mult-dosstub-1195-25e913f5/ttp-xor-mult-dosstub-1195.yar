rule TTP_XOR_MULT_DOSStub_1195 {
  strings:
    $key_1195 = { 45 fd [2] 31 e5 [2] 76 e7 [2] 31 f6 [2] 7f fa [2] 73 f0 [2] 64 fb [2] 7f b5 [2] 42 }

  condition:
    any of them
}