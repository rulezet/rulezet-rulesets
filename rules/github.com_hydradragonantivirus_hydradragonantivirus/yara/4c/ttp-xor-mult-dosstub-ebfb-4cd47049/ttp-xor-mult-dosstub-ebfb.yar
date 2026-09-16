rule TTP_XOR_MULT_DOSStub_ebfb {
  strings:
    $key_ebfb = { bf 93 [2] cb 8b [2] 8c 89 [2] cb 98 [2] 85 94 [2] 89 9e [2] 9e 95 [2] 85 db [2] b8 }

  condition:
    any of them
}