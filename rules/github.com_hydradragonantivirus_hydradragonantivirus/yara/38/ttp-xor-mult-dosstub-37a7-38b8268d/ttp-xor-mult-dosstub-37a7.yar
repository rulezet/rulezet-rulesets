rule TTP_XOR_MULT_DOSStub_37a7 {
  strings:
    $key_37a7 = { 63 cf [2] 17 d7 [2] 50 d5 [2] 17 c4 [2] 59 c8 [2] 55 c2 [2] 42 c9 [2] 59 87 [2] 64 }

  condition:
    any of them
}