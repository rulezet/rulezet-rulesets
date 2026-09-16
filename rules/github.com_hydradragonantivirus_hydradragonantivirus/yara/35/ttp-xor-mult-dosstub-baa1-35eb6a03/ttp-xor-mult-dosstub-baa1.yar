rule TTP_XOR_MULT_DOSStub_baa1 {
  strings:
    $key_baa1 = { ee c9 [2] 9a d1 [2] dd d3 [2] 9a c2 [2] d4 ce [2] d8 c4 [2] cf cf [2] d4 81 [2] e9 }

  condition:
    any of them
}