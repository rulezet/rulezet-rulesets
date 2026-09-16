rule TTP_XOR_MULT_DOSStub_eb02 {
  strings:
    $key_eb02 = { bf 6a [2] cb 72 [2] 8c 70 [2] cb 61 [2] 85 6d [2] 89 67 [2] 9e 6c [2] 85 22 [2] b8 }

  condition:
    any of them
}