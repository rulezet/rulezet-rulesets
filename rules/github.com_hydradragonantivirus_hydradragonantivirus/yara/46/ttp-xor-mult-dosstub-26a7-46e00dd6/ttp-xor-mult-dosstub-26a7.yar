rule TTP_XOR_MULT_DOSStub_26a7 {
  strings:
    $key_26a7 = { 72 cf [2] 06 d7 [2] 41 d5 [2] 06 c4 [2] 48 c8 [2] 44 c2 [2] 53 c9 [2] 48 87 [2] 75 }

  condition:
    any of them
}