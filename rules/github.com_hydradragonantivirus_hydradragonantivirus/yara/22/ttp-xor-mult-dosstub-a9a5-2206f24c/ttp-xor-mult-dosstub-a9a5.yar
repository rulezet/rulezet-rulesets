rule TTP_XOR_MULT_DOSStub_a9a5 {
  strings:
    $key_a9a5 = { fd cd [2] 89 d5 [2] ce d7 [2] 89 c6 [2] c7 ca [2] cb c0 [2] dc cb [2] c7 85 [2] fa }

  condition:
    any of them
}