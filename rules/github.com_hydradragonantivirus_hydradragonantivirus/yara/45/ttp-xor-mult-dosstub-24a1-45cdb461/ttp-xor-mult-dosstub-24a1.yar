rule TTP_XOR_MULT_DOSStub_24a1 {
  strings:
    $key_24a1 = { 70 c9 [2] 04 d1 [2] 43 d3 [2] 04 c2 [2] 4a ce [2] 46 c4 [2] 51 cf [2] 4a 81 [2] 77 }

  condition:
    any of them
}