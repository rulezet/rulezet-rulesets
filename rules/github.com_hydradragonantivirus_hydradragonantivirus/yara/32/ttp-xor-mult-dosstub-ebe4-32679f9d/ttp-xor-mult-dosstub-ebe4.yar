rule TTP_XOR_MULT_DOSStub_ebe4 {
  strings:
    $key_ebe4 = { bf 8c [2] cb 94 [2] 8c 96 [2] cb 87 [2] 85 8b [2] 89 81 [2] 9e 8a [2] 85 c4 [2] b8 }

  condition:
    any of them
}