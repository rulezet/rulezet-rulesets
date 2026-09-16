rule TTP_XOR_MULT_DOSStub_2694 {
  strings:
    $key_2694 = { 72 fc [2] 06 e4 [2] 41 e6 [2] 06 f7 [2] 48 fb [2] 44 f1 [2] 53 fa [2] 48 b4 [2] 75 }

  condition:
    any of them
}