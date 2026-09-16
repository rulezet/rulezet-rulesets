rule TTP_XOR_MULT_DOSStub_eb73 {
  strings:
    $key_eb73 = { bf 1b [2] cb 03 [2] 8c 01 [2] cb 10 [2] 85 1c [2] 89 16 [2] 9e 1d [2] 85 53 [2] b8 }

  condition:
    any of them
}