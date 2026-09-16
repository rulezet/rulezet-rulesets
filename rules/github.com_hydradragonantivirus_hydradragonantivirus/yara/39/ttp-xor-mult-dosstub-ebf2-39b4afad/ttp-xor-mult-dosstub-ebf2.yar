rule TTP_XOR_MULT_DOSStub_ebf2 {
  strings:
    $key_ebf2 = { bf 9a [2] cb 82 [2] 8c 80 [2] cb 91 [2] 85 9d [2] 89 97 [2] 9e 9c [2] 85 d2 [2] b8 }

  condition:
    any of them
}