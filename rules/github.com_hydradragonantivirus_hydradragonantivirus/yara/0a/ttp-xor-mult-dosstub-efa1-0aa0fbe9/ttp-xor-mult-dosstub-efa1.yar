rule TTP_XOR_MULT_DOSStub_efa1 {
  strings:
    $key_efa1 = { bb c9 [2] cf d1 [2] 88 d3 [2] cf c2 [2] 81 ce [2] 8d c4 [2] 9a cf [2] 81 81 [2] bc }

  condition:
    any of them
}