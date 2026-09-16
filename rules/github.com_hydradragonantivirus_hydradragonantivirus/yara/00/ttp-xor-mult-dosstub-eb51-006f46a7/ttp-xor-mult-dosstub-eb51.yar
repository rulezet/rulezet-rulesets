rule TTP_XOR_MULT_DOSStub_eb51 {
  strings:
    $key_eb51 = { bf 39 [2] cb 21 [2] 8c 23 [2] cb 32 [2] 85 3e [2] 89 34 [2] 9e 3f [2] 85 71 [2] b8 }

  condition:
    any of them
}