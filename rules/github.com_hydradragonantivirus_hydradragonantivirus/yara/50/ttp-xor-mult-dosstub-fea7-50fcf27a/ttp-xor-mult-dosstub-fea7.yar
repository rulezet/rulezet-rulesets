rule TTP_XOR_MULT_DOSStub_fea7 {
  strings:
    $key_fea7 = { aa cf [2] de d7 [2] 99 d5 [2] de c4 [2] 90 c8 [2] 9c c2 [2] 8b c9 [2] 90 87 [2] ad }

  condition:
    any of them
}