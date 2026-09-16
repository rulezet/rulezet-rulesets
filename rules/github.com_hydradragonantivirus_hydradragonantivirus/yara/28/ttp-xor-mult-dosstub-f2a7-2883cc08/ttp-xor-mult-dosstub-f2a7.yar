rule TTP_XOR_MULT_DOSStub_f2a7 {
  strings:
    $key_f2a7 = { a6 cf [2] d2 d7 [2] 95 d5 [2] d2 c4 [2] 9c c8 [2] 90 c2 [2] 87 c9 [2] 9c 87 [2] a1 }

  condition:
    any of them
}