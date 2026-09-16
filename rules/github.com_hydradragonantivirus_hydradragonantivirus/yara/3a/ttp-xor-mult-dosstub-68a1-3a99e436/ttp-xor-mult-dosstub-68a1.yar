rule TTP_XOR_MULT_DOSStub_68a1 {
  strings:
    $key_68a1 = { 3c c9 [2] 48 d1 [2] 0f d3 [2] 48 c2 [2] 06 ce [2] 0a c4 [2] 1d cf [2] 06 81 [2] 3b }

  condition:
    any of them
}