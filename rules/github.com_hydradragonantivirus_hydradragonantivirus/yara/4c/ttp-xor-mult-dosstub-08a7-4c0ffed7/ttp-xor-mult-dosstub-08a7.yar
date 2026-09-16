rule TTP_XOR_MULT_DOSStub_08a7 {
  strings:
    $key_08a7 = { 5c cf [2] 28 d7 [2] 6f d5 [2] 28 c4 [2] 66 c8 [2] 6a c2 [2] 7d c9 [2] 66 87 [2] 5b }

  condition:
    any of them
}