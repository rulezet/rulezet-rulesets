rule TTP_XOR_MULT_DOSStub_eb0c {
  strings:
    $key_eb0c = { bf 64 [2] cb 7c [2] 8c 7e [2] cb 6f [2] 85 63 [2] 89 69 [2] 9e 62 [2] 85 2c [2] b8 }

  condition:
    any of them
}