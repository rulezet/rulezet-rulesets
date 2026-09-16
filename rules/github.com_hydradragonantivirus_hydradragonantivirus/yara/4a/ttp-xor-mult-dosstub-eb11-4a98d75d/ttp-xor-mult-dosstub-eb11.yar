rule TTP_XOR_MULT_DOSStub_eb11 {
  strings:
    $key_eb11 = { bf 79 [2] cb 61 [2] 8c 63 [2] cb 72 [2] 85 7e [2] 89 74 [2] 9e 7f [2] 85 31 [2] b8 }

  condition:
    any of them
}