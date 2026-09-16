rule TTP_XOR_MULT_DOSStub_28a1 {
  strings:
    $key_28a1 = { 7c c9 [2] 08 d1 [2] 4f d3 [2] 08 c2 [2] 46 ce [2] 4a c4 [2] 5d cf [2] 46 81 [2] 7b }

  condition:
    any of them
}