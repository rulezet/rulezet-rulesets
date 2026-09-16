rule TTP_XOR_MULT_DOSStub_15a1 {
  strings:
    $key_15a1 = { 41 c9 [2] 35 d1 [2] 72 d3 [2] 35 c2 [2] 7b ce [2] 77 c4 [2] 60 cf [2] 7b 81 [2] 46 }

  condition:
    any of them
}