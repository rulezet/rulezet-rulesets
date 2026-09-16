rule TTP_XOR_MULT_DOSStub_5194 {
  strings:
    $key_5194 = { 05 fc [2] 71 e4 [2] 36 e6 [2] 71 f7 [2] 3f fb [2] 33 f1 [2] 24 fa [2] 3f b4 [2] 02 }

  condition:
    any of them
}