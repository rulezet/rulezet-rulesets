rule TTP_XOR_MULT_DOSStub_eb77 {
  strings:
    $key_eb77 = { bf 1f [2] cb 07 [2] 8c 05 [2] cb 14 [2] 85 18 [2] 89 12 [2] 9e 19 [2] 85 57 [2] b8 }

  condition:
    any of them
}