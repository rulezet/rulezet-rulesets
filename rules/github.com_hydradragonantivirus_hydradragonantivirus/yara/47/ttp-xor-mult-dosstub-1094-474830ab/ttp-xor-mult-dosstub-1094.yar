rule TTP_XOR_MULT_DOSStub_1094 {
  strings:
    $key_1094 = { 44 fc [2] 30 e4 [2] 77 e6 [2] 30 f7 [2] 7e fb [2] 72 f1 [2] 65 fa [2] 7e b4 [2] 43 }

  condition:
    any of them
}