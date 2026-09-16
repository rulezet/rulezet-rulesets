rule TTP_XOR_MULT_DOSStub_eb79 {
  strings:
    $key_eb79 = { bf 11 [2] cb 09 [2] 8c 0b [2] cb 1a [2] 85 16 [2] 89 1c [2] 9e 17 [2] 85 59 [2] b8 }

  condition:
    any of them
}