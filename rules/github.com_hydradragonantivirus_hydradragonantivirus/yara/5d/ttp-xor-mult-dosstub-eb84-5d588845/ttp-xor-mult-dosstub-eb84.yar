rule TTP_XOR_MULT_DOSStub_eb84 {
  strings:
    $key_eb84 = { bf ec [2] cb f4 [2] 8c f6 [2] cb e7 [2] 85 eb [2] 89 e1 [2] 9e ea [2] 85 a4 [2] b8 }

  condition:
    any of them
}