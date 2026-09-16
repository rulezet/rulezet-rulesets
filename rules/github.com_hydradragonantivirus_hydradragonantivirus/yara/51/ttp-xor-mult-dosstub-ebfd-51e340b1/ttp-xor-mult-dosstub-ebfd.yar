rule TTP_XOR_MULT_DOSStub_ebfd {
  strings:
    $key_ebfd = { bf 95 [2] cb 8d [2] 8c 8f [2] cb 9e [2] 85 92 [2] 89 98 [2] 9e 93 [2] 85 dd [2] b8 }

  condition:
    any of them
}