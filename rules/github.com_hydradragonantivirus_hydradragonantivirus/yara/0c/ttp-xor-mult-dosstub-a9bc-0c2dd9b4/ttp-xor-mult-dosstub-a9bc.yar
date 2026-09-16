rule TTP_XOR_MULT_DOSStub_a9bc {
  strings:
    $key_a9bc = { fd d4 [2] 89 cc [2] ce ce [2] 89 df [2] c7 d3 [2] cb d9 [2] dc d2 [2] c7 9c [2] fa }

  condition:
    any of them
}