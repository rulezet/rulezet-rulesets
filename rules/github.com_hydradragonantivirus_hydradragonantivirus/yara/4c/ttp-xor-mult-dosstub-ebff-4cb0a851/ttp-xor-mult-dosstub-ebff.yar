rule TTP_XOR_MULT_DOSStub_ebff {
  strings:
    $key_ebff = { bf 97 [2] cb 8f [2] 8c 8d [2] cb 9c [2] 85 90 [2] 89 9a [2] 9e 91 [2] 85 df [2] b8 }

  condition:
    any of them
}