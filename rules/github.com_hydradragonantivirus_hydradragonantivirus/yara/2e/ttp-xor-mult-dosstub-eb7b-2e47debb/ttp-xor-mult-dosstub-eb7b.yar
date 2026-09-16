rule TTP_XOR_MULT_DOSStub_eb7b {
  strings:
    $key_eb7b = { bf 13 [2] cb 0b [2] 8c 09 [2] cb 18 [2] 85 14 [2] 89 1e [2] 9e 15 [2] 85 5b [2] b8 }

  condition:
    any of them
}