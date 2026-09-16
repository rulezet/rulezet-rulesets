rule TTP_XOR_MULT_DOSStub_eb4b {
  strings:
    $key_eb4b = { bf 23 [2] cb 3b [2] 8c 39 [2] cb 28 [2] 85 24 [2] 89 2e [2] 9e 25 [2] 85 6b [2] b8 }

  condition:
    any of them
}