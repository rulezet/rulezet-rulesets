rule TTP_XOR_MULT_DOSStub_eb22 {
  strings:
    $key_eb22 = { bf 4a [2] cb 52 [2] 8c 50 [2] cb 41 [2] 85 4d [2] 89 47 [2] 9e 4c [2] 85 02 [2] b8 }

  condition:
    any of them
}