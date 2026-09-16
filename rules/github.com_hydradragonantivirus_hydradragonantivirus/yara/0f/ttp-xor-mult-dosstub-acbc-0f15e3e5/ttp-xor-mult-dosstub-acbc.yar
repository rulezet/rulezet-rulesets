rule TTP_XOR_MULT_DOSStub_acbc {
  strings:
    $key_acbc = { f8 d4 [2] 8c cc [2] cb ce [2] 8c df [2] c2 d3 [2] ce d9 [2] d9 d2 [2] c2 9c [2] ff }

  condition:
    any of them
}