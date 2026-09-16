rule TTP_XOR_MULT_DOSStub_19a1 {
  strings:
    $key_19a1 = { 4d c9 [2] 39 d1 [2] 7e d3 [2] 39 c2 [2] 77 ce [2] 7b c4 [2] 6c cf [2] 77 81 [2] 4a }

  condition:
    any of them
}