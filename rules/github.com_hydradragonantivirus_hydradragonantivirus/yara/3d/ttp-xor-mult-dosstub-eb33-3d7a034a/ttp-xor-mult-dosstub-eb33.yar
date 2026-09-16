rule TTP_XOR_MULT_DOSStub_eb33 {
  strings:
    $key_eb33 = { bf 5b [2] cb 43 [2] 8c 41 [2] cb 50 [2] 85 5c [2] 89 56 [2] 9e 5d [2] 85 13 [2] b8 }

  condition:
    any of them
}