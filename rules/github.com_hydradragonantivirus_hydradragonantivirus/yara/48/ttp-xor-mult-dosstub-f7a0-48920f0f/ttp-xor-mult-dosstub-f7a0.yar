rule TTP_XOR_MULT_DOSStub_f7a0 {
  strings:
    $key_f7a0 = { a3 c8 [2] d7 d0 [2] 90 d2 [2] d7 c3 [2] 99 cf [2] 95 c5 [2] 82 ce [2] 99 80 [2] a4 }

  condition:
    any of them
}