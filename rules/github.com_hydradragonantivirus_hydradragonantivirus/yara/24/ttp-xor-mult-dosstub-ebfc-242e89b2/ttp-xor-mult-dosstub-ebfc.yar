rule TTP_XOR_MULT_DOSStub_ebfc {
  strings:
    $key_ebfc = { bf 94 [2] cb 8c [2] 8c 8e [2] cb 9f [2] 85 93 [2] 89 99 [2] 9e 92 [2] 85 dc [2] b8 }

  condition:
    any of them
}