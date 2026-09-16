rule TTP_XOR_MULT_DOSStub_eb44 {
  strings:
    $key_eb44 = { bf 2c [2] cb 34 [2] 8c 36 [2] cb 27 [2] 85 2b [2] 89 21 [2] 9e 2a [2] 85 64 [2] b8 }

  condition:
    any of them
}