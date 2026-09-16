rule TTP_XOR_MULT_DOSStub_eb76 {
  strings:
    $key_eb76 = { bf 1e [2] cb 06 [2] 8c 04 [2] cb 15 [2] 85 19 [2] 89 13 [2] 9e 18 [2] 85 56 [2] b8 }

  condition:
    any of them
}