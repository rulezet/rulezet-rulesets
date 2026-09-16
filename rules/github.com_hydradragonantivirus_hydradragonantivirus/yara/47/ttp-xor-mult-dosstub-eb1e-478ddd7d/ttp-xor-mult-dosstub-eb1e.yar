rule TTP_XOR_MULT_DOSStub_eb1e {
  strings:
    $key_eb1e = { bf 76 [2] cb 6e [2] 8c 6c [2] cb 7d [2] 85 71 [2] 89 7b [2] 9e 70 [2] 85 3e [2] b8 }

  condition:
    any of them
}