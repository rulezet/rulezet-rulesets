rule TTP_XOR_MULT_DOSStub_ebe0 {
  strings:
    $key_ebe0 = { bf 88 [2] cb 90 [2] 8c 92 [2] cb 83 [2] 85 8f [2] 89 85 [2] 9e 8e [2] 85 c0 [2] b8 }

  condition:
    any of them
}