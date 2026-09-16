rule TTP_XOR_MULT_DOSStub_eb21 {
  strings:
    $key_eb21 = { bf 49 [2] cb 51 [2] 8c 53 [2] cb 42 [2] 85 4e [2] 89 44 [2] 9e 4f [2] 85 01 [2] b8 }

  condition:
    any of them
}