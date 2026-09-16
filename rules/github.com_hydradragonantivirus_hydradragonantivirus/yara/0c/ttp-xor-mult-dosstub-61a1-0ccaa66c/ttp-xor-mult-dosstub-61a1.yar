rule TTP_XOR_MULT_DOSStub_61a1 {
  strings:
    $key_61a1 = { 35 c9 [2] 41 d1 [2] 06 d3 [2] 41 c2 [2] 0f ce [2] 03 c4 [2] 14 cf [2] 0f 81 [2] 32 }

  condition:
    any of them
}