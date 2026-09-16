rule TTP_XOR_MULT_DOSStub_eb52 {
  strings:
    $key_eb52 = { bf 3a [2] cb 22 [2] 8c 20 [2] cb 31 [2] 85 3d [2] 89 37 [2] 9e 3c [2] 85 72 [2] b8 }

  condition:
    any of them
}