rule TTP_XOR_MULT_DOSStub_eb3e {
  strings:
    $key_eb3e = { bf 56 [2] cb 4e [2] 8c 4c [2] cb 5d [2] 85 51 [2] 89 5b [2] 9e 50 [2] 85 1e [2] b8 }

  condition:
    any of them
}