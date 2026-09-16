rule TTP_XOR_MULT_DOSStub_05a7 {
  strings:
    $key_05a7 = { 51 cf [2] 25 d7 [2] 62 d5 [2] 25 c4 [2] 6b c8 [2] 67 c2 [2] 70 c9 [2] 6b 87 [2] 56 }

  condition:
    any of them
}