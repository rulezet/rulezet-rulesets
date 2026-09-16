rule TTP_XOR_MULT_DOSStub_ebf4 {
  strings:
    $key_ebf4 = { bf 9c [2] cb 84 [2] 8c 86 [2] cb 97 [2] 85 9b [2] 89 91 [2] 9e 9a [2] 85 d4 [2] b8 }

  condition:
    any of them
}