rule TTP_XOR_MULT_DOSStub_5095 {
  strings:
    $key_5095 = { 04 fd [2] 70 e5 [2] 37 e7 [2] 70 f6 [2] 3e fa [2] 32 f0 [2] 25 fb [2] 3e b5 [2] 03 }

  condition:
    any of them
}