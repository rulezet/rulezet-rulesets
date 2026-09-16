rule TTP_XOR_MULT_DOSStub_eb37 {
  strings:
    $key_eb37 = { bf 5f [2] cb 47 [2] 8c 45 [2] cb 54 [2] 85 58 [2] 89 52 [2] 9e 59 [2] 85 17 [2] b8 }

  condition:
    any of them
}