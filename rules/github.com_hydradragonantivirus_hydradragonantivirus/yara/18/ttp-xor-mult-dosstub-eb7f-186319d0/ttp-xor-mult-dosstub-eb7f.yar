rule TTP_XOR_MULT_DOSStub_eb7f {
  strings:
    $key_eb7f = { bf 17 [2] cb 0f [2] 8c 0d [2] cb 1c [2] 85 10 [2] 89 1a [2] 9e 11 [2] 85 5f [2] b8 }

  condition:
    any of them
}