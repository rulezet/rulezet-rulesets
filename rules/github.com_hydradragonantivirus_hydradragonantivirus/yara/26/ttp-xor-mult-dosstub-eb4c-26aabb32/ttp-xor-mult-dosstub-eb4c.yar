rule TTP_XOR_MULT_DOSStub_eb4c {
  strings:
    $key_eb4c = { bf 24 [2] cb 3c [2] 8c 3e [2] cb 2f [2] 85 23 [2] 89 29 [2] 9e 22 [2] 85 6c [2] b8 }

  condition:
    any of them
}