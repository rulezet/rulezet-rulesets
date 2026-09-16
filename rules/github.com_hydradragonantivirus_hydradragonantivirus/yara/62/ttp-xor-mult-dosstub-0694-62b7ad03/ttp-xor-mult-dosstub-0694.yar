rule TTP_XOR_MULT_DOSStub_0694 {
  strings:
    $key_0694 = { 52 fc [2] 26 e4 [2] 61 e6 [2] 26 f7 [2] 68 fb [2] 64 f1 [2] 73 fa [2] 68 b4 [2] 55 }

  condition:
    any of them
}