rule TTP_XOR_MULT_DOSStub_ebfe {
  strings:
    $key_ebfe = { bf 96 [2] cb 8e [2] 8c 8c [2] cb 9d [2] 85 91 [2] 89 9b [2] 9e 90 [2] 85 de [2] b8 }

  condition:
    any of them
}