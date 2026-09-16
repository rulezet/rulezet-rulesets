rule TTP_XOR_MULT_DOSStub_bba0 {
  strings:
    $key_bba0 = { ef c8 [2] 9b d0 [2] dc d2 [2] 9b c3 [2] d5 cf [2] d9 c5 [2] ce ce [2] d5 80 [2] e8 }

  condition:
    any of them
}