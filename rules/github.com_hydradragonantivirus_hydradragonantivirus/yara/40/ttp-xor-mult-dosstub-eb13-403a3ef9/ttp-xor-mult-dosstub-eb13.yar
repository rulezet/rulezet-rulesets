rule TTP_XOR_MULT_DOSStub_eb13 {
  strings:
    $key_eb13 = { bf 7b [2] cb 63 [2] 8c 61 [2] cb 70 [2] 85 7c [2] 89 76 [2] 9e 7d [2] 85 33 [2] b8 }

  condition:
    any of them
}