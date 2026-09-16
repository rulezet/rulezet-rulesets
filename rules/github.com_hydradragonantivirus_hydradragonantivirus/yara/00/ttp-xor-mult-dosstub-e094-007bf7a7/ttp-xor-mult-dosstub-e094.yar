rule TTP_XOR_MULT_DOSStub_e094 {
  strings:
    $key_e094 = { b4 fc [2] c0 e4 [2] 87 e6 [2] c0 f7 [2] 8e fb [2] 82 f1 [2] 95 fa [2] 8e b4 [2] b3 }

  condition:
    any of them
}