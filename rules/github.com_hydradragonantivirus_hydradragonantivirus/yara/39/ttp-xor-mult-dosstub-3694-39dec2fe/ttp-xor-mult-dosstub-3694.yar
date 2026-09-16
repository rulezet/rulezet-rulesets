rule TTP_XOR_MULT_DOSStub_3694 {
  strings:
    $key_3694 = { 62 fc [2] 16 e4 [2] 51 e6 [2] 16 f7 [2] 58 fb [2] 54 f1 [2] 43 fa [2] 58 b4 [2] 65 }

  condition:
    any of them
}