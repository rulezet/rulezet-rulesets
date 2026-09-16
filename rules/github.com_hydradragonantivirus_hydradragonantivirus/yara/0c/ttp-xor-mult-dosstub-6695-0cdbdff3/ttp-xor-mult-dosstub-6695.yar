rule TTP_XOR_MULT_DOSStub_6695 {
  strings:
    $key_6695 = { 32 fd [2] 46 e5 [2] 01 e7 [2] 46 f6 [2] 08 fa [2] 04 f0 [2] 13 fb [2] 08 b5 [2] 35 }

  condition:
    any of them
}