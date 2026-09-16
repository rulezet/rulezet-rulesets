rule TTP_XOR_MULT_DOSStub_eb6a {
  strings:
    $key_eb6a = { bf 02 [2] cb 1a [2] 8c 18 [2] cb 09 [2] 85 05 [2] 89 0f [2] 9e 04 [2] 85 4a [2] b8 }

  condition:
    any of them
}