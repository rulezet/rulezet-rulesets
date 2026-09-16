rule TTP_XOR_MULT_DOSStub_f3a1 {
  strings:
    $key_f3a1 = { a7 c9 [2] d3 d1 [2] 94 d3 [2] d3 c2 [2] 9d ce [2] 91 c4 [2] 86 cf [2] 9d 81 [2] a0 }

  condition:
    any of them
}