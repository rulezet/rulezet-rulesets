rule TTP_XOR_MULT_DOSStub_eb65 {
  strings:
    $key_eb65 = { bf 0d [2] cb 15 [2] 8c 17 [2] cb 06 [2] 85 0a [2] 89 00 [2] 9e 0b [2] 85 45 [2] b8 }

  condition:
    any of them
}