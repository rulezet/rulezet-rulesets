rule TTP_XOR_MULT_DOSStub_eb5c {
  strings:
    $key_eb5c = { bf 34 [2] cb 2c [2] 8c 2e [2] cb 3f [2] 85 33 [2] 89 39 [2] 9e 32 [2] 85 7c [2] b8 }

  condition:
    any of them
}