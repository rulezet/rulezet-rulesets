rule TTP_XOR_MULT_DOSStub_5094 {
  strings:
    $key_5094 = { 04 fc [2] 70 e4 [2] 37 e6 [2] 70 f7 [2] 3e fb [2] 32 f1 [2] 25 fa [2] 3e b4 [2] 03 }

  condition:
    any of them
}