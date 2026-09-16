rule TTP_XOR_MULT_DOSStub_28a7 {
  strings:
    $key_28a7 = { 7c cf [2] 08 d7 [2] 4f d5 [2] 08 c4 [2] 46 c8 [2] 4a c2 [2] 5d c9 [2] 46 87 [2] 7b }

  condition:
    any of them
}