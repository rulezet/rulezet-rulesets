rule TTP_XOR_MULT_DOSStub_eb5b {
  strings:
    $key_eb5b = { bf 33 [2] cb 2b [2] 8c 29 [2] cb 38 [2] 85 34 [2] 89 3e [2] 9e 35 [2] 85 7b [2] b8 }

  condition:
    any of them
}