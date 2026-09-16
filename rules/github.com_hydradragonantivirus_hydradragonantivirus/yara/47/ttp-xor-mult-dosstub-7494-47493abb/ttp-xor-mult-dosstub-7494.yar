rule TTP_XOR_MULT_DOSStub_7494 {
  strings:
    $key_7494 = { 20 fc [2] 54 e4 [2] 13 e6 [2] 54 f7 [2] 1a fb [2] 16 f1 [2] 01 fa [2] 1a b4 [2] 27 }

  condition:
    any of them
}