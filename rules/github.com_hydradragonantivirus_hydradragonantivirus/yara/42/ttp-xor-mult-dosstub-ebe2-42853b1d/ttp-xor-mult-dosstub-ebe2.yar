rule TTP_XOR_MULT_DOSStub_ebe2 {
  strings:
    $key_ebe2 = { bf 8a [2] cb 92 [2] 8c 90 [2] cb 81 [2] 85 8d [2] 89 87 [2] 9e 8c [2] 85 c2 [2] b8 }

  condition:
    any of them
}