rule TTP_XOR_MULT_DOSStub_eb66 {
  strings:
    $key_eb66 = { bf 0e [2] cb 16 [2] 8c 14 [2] cb 05 [2] 85 09 [2] 89 03 [2] 9e 08 [2] 85 46 [2] b8 }

  condition:
    any of them
}