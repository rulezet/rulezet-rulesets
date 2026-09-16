rule TTP_XOR_MULT_DOSStub_6794 {
  strings:
    $key_6794 = { 33 fc [2] 47 e4 [2] 00 e6 [2] 47 f7 [2] 09 fb [2] 05 f1 [2] 12 fa [2] 09 b4 [2] 34 }

  condition:
    any of them
}