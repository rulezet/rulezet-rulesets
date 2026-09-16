rule TTP_XOR_MULT_DOSStub_eb94 {
  strings:
    $key_eb94 = { bf fc [2] cb e4 [2] 8c e6 [2] cb f7 [2] 85 fb [2] 89 f1 [2] 9e fa [2] 85 b4 [2] b8 }

  condition:
    any of them
}