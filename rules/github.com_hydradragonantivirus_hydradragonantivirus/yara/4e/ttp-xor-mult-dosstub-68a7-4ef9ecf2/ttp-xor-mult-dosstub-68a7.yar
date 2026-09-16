rule TTP_XOR_MULT_DOSStub_68a7 {
  strings:
    $key_68a7 = { 3c cf [2] 48 d7 [2] 0f d5 [2] 48 c4 [2] 06 c8 [2] 0a c2 [2] 1d c9 [2] 06 87 [2] 3b }

  condition:
    any of them
}