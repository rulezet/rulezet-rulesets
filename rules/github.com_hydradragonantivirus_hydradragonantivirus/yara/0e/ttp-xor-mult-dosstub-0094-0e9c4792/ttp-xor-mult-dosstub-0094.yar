rule TTP_XOR_MULT_DOSStub_0094 {
  strings:
    $key_0094 = { 54 fc [2] 20 e4 [2] 67 e6 [2] 20 f7 [2] 6e fb [2] 62 f1 [2] 75 fa [2] 6e b4 [2] 53 }

  condition:
    any of them
}