rule TTP_XOR_MULT_DOSStub_eb5f {
  strings:
    $key_eb5f = { bf 37 [2] cb 2f [2] 8c 2d [2] cb 3c [2] 85 30 [2] 89 3a [2] 9e 31 [2] 85 7f [2] b8 }

  condition:
    any of them
}