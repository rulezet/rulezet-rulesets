rule TTP_XOR_MULT_DOSStub_eb14 {
  strings:
    $key_eb14 = { bf 7c [2] cb 64 [2] 8c 66 [2] cb 77 [2] 85 7b [2] 89 71 [2] 9e 7a [2] 85 34 [2] b8 }

  condition:
    any of them
}