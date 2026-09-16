rule TTP_XOR_MULT_DOSStub_06a7 {
  strings:
    $key_06a7 = { 52 cf [2] 26 d7 [2] 61 d5 [2] 26 c4 [2] 68 c8 [2] 64 c2 [2] 73 c9 [2] 68 87 [2] 55 }

  condition:
    any of them
}