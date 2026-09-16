rule TTP_XOR_MULT_DOSStub_bba7 {
  strings:
    $key_bba7 = { ef cf [2] 9b d7 [2] dc d5 [2] 9b c4 [2] d5 c8 [2] d9 c2 [2] ce c9 [2] d5 87 [2] e8 }

  condition:
    any of them
}