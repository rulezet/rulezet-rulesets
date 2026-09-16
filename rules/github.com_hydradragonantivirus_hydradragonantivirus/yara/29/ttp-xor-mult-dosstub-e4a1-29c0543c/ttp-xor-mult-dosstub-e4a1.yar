rule TTP_XOR_MULT_DOSStub_e4a1 {
  strings:
    $key_e4a1 = { b0 c9 [2] c4 d1 [2] 83 d3 [2] c4 c2 [2] 8a ce [2] 86 c4 [2] 91 cf [2] 8a 81 [2] b7 }

  condition:
    any of them
}