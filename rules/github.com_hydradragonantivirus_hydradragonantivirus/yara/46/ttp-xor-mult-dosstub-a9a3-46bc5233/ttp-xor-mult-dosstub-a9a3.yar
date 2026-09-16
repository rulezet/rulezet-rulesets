rule TTP_XOR_MULT_DOSStub_a9a3 {
  strings:
    $key_a9a3 = { fd cb [2] 89 d3 [2] ce d1 [2] 89 c0 [2] c7 cc [2] cb c6 [2] dc cd [2] c7 83 [2] fa }

  condition:
    any of them
}