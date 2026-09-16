rule TTP_XOR_MULT_DOSStub_eb85 {
  strings:
    $key_eb85 = { bf ed [2] cb f5 [2] 8c f7 [2] cb e6 [2] 85 ea [2] 89 e0 [2] 9e eb [2] 85 a5 [2] b8 }

  condition:
    any of them
}