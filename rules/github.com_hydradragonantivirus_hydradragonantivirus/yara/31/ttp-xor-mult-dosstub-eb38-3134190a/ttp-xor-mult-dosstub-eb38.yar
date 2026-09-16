rule TTP_XOR_MULT_DOSStub_eb38 {
  strings:
    $key_eb38 = { bf 50 [2] cb 48 [2] 8c 4a [2] cb 5b [2] 85 57 [2] 89 5d [2] 9e 56 [2] 85 18 [2] b8 }

  condition:
    any of them
}