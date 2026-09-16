rule TTP_XOR_MULT_DOSStub_eb20 {
  strings:
    $key_eb20 = { bf 48 [2] cb 50 [2] 8c 52 [2] cb 43 [2] 85 4f [2] 89 45 [2] 9e 4e [2] 85 00 [2] b8 }

  condition:
    any of them
}