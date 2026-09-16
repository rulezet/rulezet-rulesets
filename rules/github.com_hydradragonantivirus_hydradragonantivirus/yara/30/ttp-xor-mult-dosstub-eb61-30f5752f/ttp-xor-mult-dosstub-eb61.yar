rule TTP_XOR_MULT_DOSStub_eb61 {
  strings:
    $key_eb61 = { bf 09 [2] cb 11 [2] 8c 13 [2] cb 02 [2] 85 0e [2] 89 04 [2] 9e 0f [2] 85 41 [2] b8 }

  condition:
    any of them
}