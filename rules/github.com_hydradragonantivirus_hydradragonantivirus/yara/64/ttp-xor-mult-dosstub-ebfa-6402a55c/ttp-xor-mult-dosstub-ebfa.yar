rule TTP_XOR_MULT_DOSStub_ebfa {
  strings:
    $key_ebfa = { bf 92 [2] cb 8a [2] 8c 88 [2] cb 99 [2] 85 95 [2] 89 9f [2] 9e 94 [2] 85 da [2] b8 }

  condition:
    any of them
}