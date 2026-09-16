rule TTP_XOR_MULT_DOSStub_ebec {
  strings:
    $key_ebec = { bf 84 [2] cb 9c [2] 8c 9e [2] cb 8f [2] 85 83 [2] 89 89 [2] 9e 82 [2] 85 cc [2] b8 }

  condition:
    any of them
}