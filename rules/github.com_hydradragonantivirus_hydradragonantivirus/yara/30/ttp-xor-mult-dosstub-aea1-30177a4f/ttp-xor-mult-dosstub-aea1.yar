rule TTP_XOR_MULT_DOSStub_aea1 {
  strings:
    $key_aea1 = { fa c9 [2] 8e d1 [2] c9 d3 [2] 8e c2 [2] c0 ce [2] cc c4 [2] db cf [2] c0 81 [2] fd }

  condition:
    any of them
}