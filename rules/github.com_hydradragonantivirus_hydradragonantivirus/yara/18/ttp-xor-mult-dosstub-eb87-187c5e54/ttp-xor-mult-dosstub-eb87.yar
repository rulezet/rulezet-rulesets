rule TTP_XOR_MULT_DOSStub_eb87 {
  strings:
    $key_eb87 = { bf ef [2] cb f7 [2] 8c f5 [2] cb e4 [2] 85 e8 [2] 89 e2 [2] 9e e9 [2] 85 a7 [2] b8 }

  condition:
    any of them
}