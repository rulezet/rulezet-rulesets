rule TTP_XOR_MULT_DOSStub_eb1a {
  strings:
    $key_eb1a = { bf 72 [2] cb 6a [2] 8c 68 [2] cb 79 [2] 85 75 [2] 89 7f [2] 9e 74 [2] 85 3a [2] b8 }

  condition:
    any of them
}