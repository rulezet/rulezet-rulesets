rule TTP_XOR_MULT_DOSStub_10a7 {
  strings:
    $key_10a7 = { 44 cf [2] 30 d7 [2] 77 d5 [2] 30 c4 [2] 7e c8 [2] 72 c2 [2] 65 c9 [2] 7e 87 [2] 43 }

  condition:
    any of them
}