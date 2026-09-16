rule TTP_XOR_MULT_DOSStub_eb2b {
  strings:
    $key_eb2b = { bf 43 [2] cb 5b [2] 8c 59 [2] cb 48 [2] 85 44 [2] 89 4e [2] 9e 45 [2] 85 0b [2] b8 }

  condition:
    any of them
}