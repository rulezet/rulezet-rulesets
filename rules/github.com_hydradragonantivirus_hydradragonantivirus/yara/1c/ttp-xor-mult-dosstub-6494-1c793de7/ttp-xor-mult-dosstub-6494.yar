rule TTP_XOR_MULT_DOSStub_6494 {
  strings:
    $key_6494 = { 30 fc [2] 44 e4 [2] 03 e6 [2] 44 f7 [2] 0a fb [2] 06 f1 [2] 11 fa [2] 0a b4 [2] 37 }

  condition:
    any of them
}