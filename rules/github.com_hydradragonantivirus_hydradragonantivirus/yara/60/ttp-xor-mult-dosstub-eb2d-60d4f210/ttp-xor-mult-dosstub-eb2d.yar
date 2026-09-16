rule TTP_XOR_MULT_DOSStub_eb2d {
  strings:
    $key_eb2d = { bf 45 [2] cb 5d [2] 8c 5f [2] cb 4e [2] 85 42 [2] 89 48 [2] 9e 43 [2] 85 0d [2] b8 }

  condition:
    any of them
}