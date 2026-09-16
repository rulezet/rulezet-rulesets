rule TTP_XOR_MULT_DOSStub_4194 {
  strings:
    $key_4194 = { 15 fc [2] 61 e4 [2] 26 e6 [2] 61 f7 [2] 2f fb [2] 23 f1 [2] 34 fa [2] 2f b4 [2] 12 }

  condition:
    any of them
}