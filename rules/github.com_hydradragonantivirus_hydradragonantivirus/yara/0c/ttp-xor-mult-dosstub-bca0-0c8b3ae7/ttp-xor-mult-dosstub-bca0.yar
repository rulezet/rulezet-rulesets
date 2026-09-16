rule TTP_XOR_MULT_DOSStub_bca0 {
  strings:
    $key_bca0 = { e8 c8 [2] 9c d0 [2] db d2 [2] 9c c3 [2] d2 cf [2] de c5 [2] c9 ce [2] d2 80 [2] ef }

  condition:
    any of them
}