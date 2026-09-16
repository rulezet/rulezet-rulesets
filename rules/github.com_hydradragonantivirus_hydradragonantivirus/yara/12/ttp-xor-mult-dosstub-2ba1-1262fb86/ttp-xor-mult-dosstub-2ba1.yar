rule TTP_XOR_MULT_DOSStub_2ba1 {
  strings:
    $key_2ba1 = { 7f c9 [2] 0b d1 [2] 4c d3 [2] 0b c2 [2] 45 ce [2] 49 c4 [2] 5e cf [2] 45 81 [2] 78 }

  condition:
    any of them
}