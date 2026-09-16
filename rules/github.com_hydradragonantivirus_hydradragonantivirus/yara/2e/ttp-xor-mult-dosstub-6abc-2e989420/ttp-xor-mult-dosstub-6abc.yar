rule TTP_XOR_MULT_DOSStub_6abc {
  strings:
    $key_6abc = { 3e d4 [2] 4a cc [2] 0d ce [2] 4a df [2] 04 d3 [2] 08 d9 [2] 1f d2 [2] 04 9c [2] 39 }

  condition:
    any of them
}