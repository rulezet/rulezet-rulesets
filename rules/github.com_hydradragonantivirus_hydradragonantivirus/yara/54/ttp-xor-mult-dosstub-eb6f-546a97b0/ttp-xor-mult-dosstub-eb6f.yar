rule TTP_XOR_MULT_DOSStub_eb6f {
  strings:
    $key_eb6f = { bf 07 [2] cb 1f [2] 8c 1d [2] cb 0c [2] 85 00 [2] 89 0a [2] 9e 01 [2] 85 4f [2] b8 }

  condition:
    any of them
}