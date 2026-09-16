rule TTP_XOR_MULT_DOSStub_1095 {
  strings:
    $key_1095 = { 44 fd [2] 30 e5 [2] 77 e7 [2] 30 f6 [2] 7e fa [2] 72 f0 [2] 65 fb [2] 7e b5 [2] 43 }

  condition:
    any of them
}