rule TTP_XOR_MULT_DOSStub_7195 {
  strings:
    $key_7195 = { 25 fd [2] 51 e5 [2] 16 e7 [2] 51 f6 [2] 1f fa [2] 13 f0 [2] 04 fb [2] 1f b5 [2] 22 }

  condition:
    any of them
}