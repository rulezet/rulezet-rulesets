rule TTP_XOR_MULT_DOSStub_18a1 {
  strings:
    $key_18a1 = { 4c c9 [2] 38 d1 [2] 7f d3 [2] 38 c2 [2] 76 ce [2] 7a c4 [2] 6d cf [2] 76 81 [2] 4b }

  condition:
    any of them
}