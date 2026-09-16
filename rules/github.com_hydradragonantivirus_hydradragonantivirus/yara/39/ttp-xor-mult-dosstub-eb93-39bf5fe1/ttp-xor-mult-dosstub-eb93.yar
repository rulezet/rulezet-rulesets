rule TTP_XOR_MULT_DOSStub_eb93 {
  strings:
    $key_eb93 = { bf fb [2] cb e3 [2] 8c e1 [2] cb f0 [2] 85 fc [2] 89 f6 [2] 9e fd [2] 85 b3 [2] b8 }

  condition:
    any of them
}