rule TTP_XOR_MULT_DOSStub_eb74 {
  strings:
    $key_eb74 = { bf 1c [2] cb 04 [2] 8c 06 [2] cb 17 [2] 85 1b [2] 89 11 [2] 9e 1a [2] 85 54 [2] b8 }

  condition:
    any of them
}