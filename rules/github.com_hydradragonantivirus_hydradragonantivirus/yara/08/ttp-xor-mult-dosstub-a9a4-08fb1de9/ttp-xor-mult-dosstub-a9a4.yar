rule TTP_XOR_MULT_DOSStub_a9a4 {
  strings:
    $key_a9a4 = { fd cc [2] 89 d4 [2] ce d6 [2] 89 c7 [2] c7 cb [2] cb c1 [2] dc ca [2] c7 84 [2] fa }

  condition:
    any of them
}