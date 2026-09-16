rule TTP_XOR_MULT_DOSStub_eb80 {
  strings:
    $key_eb80 = { bf e8 [2] cb f0 [2] 8c f2 [2] cb e3 [2] 85 ef [2] 89 e5 [2] 9e ee [2] 85 a0 [2] b8 }

  condition:
    any of them
}