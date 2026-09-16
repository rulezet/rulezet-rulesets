rule TTP_XOR_MULT_DOSStub_eb7c {
  strings:
    $key_eb7c = { bf 14 [2] cb 0c [2] 8c 0e [2] cb 1f [2] 85 13 [2] 89 19 [2] 9e 12 [2] 85 5c [2] b8 }

  condition:
    any of them
}