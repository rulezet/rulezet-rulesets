rule TTP_XOR_MULT_DOSStub_eb91 {
  strings:
    $key_eb91 = { bf f9 [2] cb e1 [2] 8c e3 [2] cb f2 [2] 85 fe [2] 89 f4 [2] 9e ff [2] 85 b1 [2] b8 }

  condition:
    any of them
}