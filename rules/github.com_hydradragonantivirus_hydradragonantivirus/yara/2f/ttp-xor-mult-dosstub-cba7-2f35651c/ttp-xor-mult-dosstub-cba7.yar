rule TTP_XOR_MULT_DOSStub_cba7 {
  strings:
    $key_cba7 = { 9f cf [2] eb d7 [2] ac d5 [2] eb c4 [2] a5 c8 [2] a9 c2 [2] be c9 [2] a5 87 [2] 98 }

  condition:
    any of them
}