rule TTP_XOR_MULT_DOSStub_eb17 {
  strings:
    $key_eb17 = { bf 7f [2] cb 67 [2] 8c 65 [2] cb 74 [2] 85 78 [2] 89 72 [2] 9e 79 [2] 85 37 [2] b8 }

  condition:
    any of them
}