rule TTP_XOR_MULT_DOSStub_65a1 {
  strings:
    $key_65a1 = { 31 c9 [2] 45 d1 [2] 02 d3 [2] 45 c2 [2] 0b ce [2] 07 c4 [2] 10 cf [2] 0b 81 [2] 36 }

  condition:
    any of them
}