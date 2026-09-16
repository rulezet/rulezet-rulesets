rule TTP_XOR_MULT_DOSStub_eb45 {
  strings:
    $key_eb45 = { bf 2d [2] cb 35 [2] 8c 37 [2] cb 26 [2] 85 2a [2] 89 20 [2] 9e 2b [2] 85 65 [2] b8 }

  condition:
    any of them
}