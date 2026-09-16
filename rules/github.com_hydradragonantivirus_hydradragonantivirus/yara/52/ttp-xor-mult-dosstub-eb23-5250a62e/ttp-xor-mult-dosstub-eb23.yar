rule TTP_XOR_MULT_DOSStub_eb23 {
  strings:
    $key_eb23 = { bf 4b [2] cb 53 [2] 8c 51 [2] cb 40 [2] 85 4c [2] 89 46 [2] 9e 4d [2] 85 03 [2] b8 }

  condition:
    any of them
}