rule TTP_XOR_MULT_DOSStub_eb25 {
  strings:
    $key_eb25 = { bf 4d [2] cb 55 [2] 8c 57 [2] cb 46 [2] 85 4a [2] 89 40 [2] 9e 4b [2] 85 05 [2] b8 }

  condition:
    any of them
}