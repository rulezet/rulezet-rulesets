rule TTP_XOR_MULT_DOSStub_ebf1 {
  strings:
    $key_ebf1 = { bf 99 [2] cb 81 [2] 8c 83 [2] cb 92 [2] 85 9e [2] 89 94 [2] 9e 9f [2] 85 d1 [2] b8 }

  condition:
    any of them
}