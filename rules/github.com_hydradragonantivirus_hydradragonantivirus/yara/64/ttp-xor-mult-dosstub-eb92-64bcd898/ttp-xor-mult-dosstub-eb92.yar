rule TTP_XOR_MULT_DOSStub_eb92 {
  strings:
    $key_eb92 = { bf fa [2] cb e2 [2] 8c e0 [2] cb f1 [2] 85 fd [2] 89 f7 [2] 9e fc [2] 85 b2 [2] b8 }

  condition:
    any of them
}