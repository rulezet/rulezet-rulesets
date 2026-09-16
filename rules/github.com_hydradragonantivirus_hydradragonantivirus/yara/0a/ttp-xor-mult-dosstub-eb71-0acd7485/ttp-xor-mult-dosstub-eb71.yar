rule TTP_XOR_MULT_DOSStub_eb71 {
  strings:
    $key_eb71 = { bf 19 [2] cb 01 [2] 8c 03 [2] cb 12 [2] 85 1e [2] 89 14 [2] 9e 1f [2] 85 51 [2] b8 }

  condition:
    any of them
}