rule TTP_XOR_MULT_DOSStub_eb04 {
  strings:
    $key_eb04 = { bf 6c [2] cb 74 [2] 8c 76 [2] cb 67 [2] 85 6b [2] 89 61 [2] 9e 6a [2] 85 24 [2] b8 }

  condition:
    any of them
}