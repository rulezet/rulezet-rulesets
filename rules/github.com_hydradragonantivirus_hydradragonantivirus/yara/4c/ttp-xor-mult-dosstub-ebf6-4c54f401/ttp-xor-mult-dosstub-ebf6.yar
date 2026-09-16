rule TTP_XOR_MULT_DOSStub_ebf6 {
  strings:
    $key_ebf6 = { bf 9e [2] cb 86 [2] 8c 84 [2] cb 95 [2] 85 99 [2] 89 93 [2] 9e 98 [2] 85 d6 [2] b8 }

  condition:
    any of them
}