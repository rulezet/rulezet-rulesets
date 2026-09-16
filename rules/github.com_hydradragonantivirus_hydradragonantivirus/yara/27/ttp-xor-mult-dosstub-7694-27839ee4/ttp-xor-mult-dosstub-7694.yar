rule TTP_XOR_MULT_DOSStub_7694 {
  strings:
    $key_7694 = { 22 fc [2] 56 e4 [2] 11 e6 [2] 56 f7 [2] 18 fb [2] 14 f1 [2] 03 fa [2] 18 b4 [2] 25 }

  condition:
    any of them
}