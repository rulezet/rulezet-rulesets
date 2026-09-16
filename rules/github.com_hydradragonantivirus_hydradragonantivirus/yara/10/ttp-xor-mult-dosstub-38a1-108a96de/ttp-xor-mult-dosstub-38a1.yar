rule TTP_XOR_MULT_DOSStub_38a1 {
  strings:
    $key_38a1 = { 6c c9 [2] 18 d1 [2] 5f d3 [2] 18 c2 [2] 56 ce [2] 5a c4 [2] 4d cf [2] 56 81 [2] 6b }

  condition:
    any of them
}