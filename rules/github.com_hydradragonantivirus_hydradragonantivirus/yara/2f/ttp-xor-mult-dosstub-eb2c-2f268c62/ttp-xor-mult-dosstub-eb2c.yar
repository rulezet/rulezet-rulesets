rule TTP_XOR_MULT_DOSStub_eb2c {
  strings:
    $key_eb2c = { bf 44 [2] cb 5c [2] 8c 5e [2] cb 4f [2] 85 43 [2] 89 49 [2] 9e 42 [2] 85 0c [2] b8 }

  condition:
    any of them
}