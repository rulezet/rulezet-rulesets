rule TTP_XOR_MULT_DOSStub_65a7 {
  strings:
    $key_65a7 = { 31 cf [2] 45 d7 [2] 02 d5 [2] 45 c4 [2] 0b c8 [2] 07 c2 [2] 10 c9 [2] 0b 87 [2] 36 }

  condition:
    any of them
}