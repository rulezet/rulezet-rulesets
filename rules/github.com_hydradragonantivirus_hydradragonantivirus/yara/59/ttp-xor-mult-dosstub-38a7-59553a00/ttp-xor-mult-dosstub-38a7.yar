rule TTP_XOR_MULT_DOSStub_38a7 {
  strings:
    $key_38a7 = { 6c cf [2] 18 d7 [2] 5f d5 [2] 18 c4 [2] 56 c8 [2] 5a c2 [2] 4d c9 [2] 56 87 [2] 6b }

  condition:
    any of them
}