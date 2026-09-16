rule TTP_XOR_MULT_DOSStub_ebee {
  strings:
    $key_ebee = { bf 86 [2] cb 9e [2] 8c 9c [2] cb 8d [2] 85 81 [2] 89 8b [2] 9e 80 [2] 85 ce [2] b8 }

  condition:
    any of them
}