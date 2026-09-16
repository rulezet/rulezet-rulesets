rule TTP_XOR_MULT_DOSStub_eb08 {
  strings:
    $key_eb08 = { bf 60 [2] cb 78 [2] 8c 7a [2] cb 6b [2] 85 67 [2] 89 6d [2] 9e 66 [2] 85 28 [2] b8 }

  condition:
    any of them
}