rule TTP_XOR_MULT_DOSStub_eb90 {
  strings:
    $key_eb90 = { bf f8 [2] cb e0 [2] 8c e2 [2] cb f3 [2] 85 ff [2] 89 f5 [2] 9e fe [2] 85 b0 [2] b8 }

  condition:
    any of them
}