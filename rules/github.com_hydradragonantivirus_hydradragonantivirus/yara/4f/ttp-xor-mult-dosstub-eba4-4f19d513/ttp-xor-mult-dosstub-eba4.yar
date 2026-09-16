rule TTP_XOR_MULT_DOSStub_eba4 {
  strings:
    $key_eba4 = { bf cc [2] cb d4 [2] 8c d6 [2] cb c7 [2] 85 cb [2] 89 c1 [2] 9e ca [2] 85 84 [2] b8 }

  condition:
    any of them
}