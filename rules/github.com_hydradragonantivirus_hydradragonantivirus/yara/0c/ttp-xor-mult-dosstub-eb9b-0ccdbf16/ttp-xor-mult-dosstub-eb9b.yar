rule TTP_XOR_MULT_DOSStub_eb9b {
  strings:
    $key_eb9b = { bf f3 [2] cb eb [2] 8c e9 [2] cb f8 [2] 85 f4 [2] 89 fe [2] 9e f5 [2] 85 bb [2] b8 }

  condition:
    any of them
}