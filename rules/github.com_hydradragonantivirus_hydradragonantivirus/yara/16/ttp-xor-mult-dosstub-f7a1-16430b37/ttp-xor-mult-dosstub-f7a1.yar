rule TTP_XOR_MULT_DOSStub_f7a1 {
  strings:
    $key_f7a1 = { a3 c9 [2] d7 d1 [2] 90 d3 [2] d7 c2 [2] 99 ce [2] 95 c4 [2] 82 cf [2] 99 81 [2] a4 }

  condition:
    any of them
}