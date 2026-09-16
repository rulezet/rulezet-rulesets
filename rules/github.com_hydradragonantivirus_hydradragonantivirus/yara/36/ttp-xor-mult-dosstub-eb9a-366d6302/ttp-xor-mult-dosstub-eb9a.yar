rule TTP_XOR_MULT_DOSStub_eb9a {
  strings:
    $key_eb9a = { bf f2 [2] cb ea [2] 8c e8 [2] cb f9 [2] 85 f5 [2] 89 ff [2] 9e f4 [2] 85 ba [2] b8 }

  condition:
    any of them
}