rule TTP_XOR_MULT_DOSStub_eb89 {
  strings:
    $key_eb89 = { bf e1 [2] cb f9 [2] 8c fb [2] cb ea [2] 85 e6 [2] 89 ec [2] 9e e7 [2] 85 a9 [2] b8 }

  condition:
    any of them
}