rule TTP_XOR_MULT_DOSStub_72a7 {
  strings:
    $key_72a7 = { 26 cf [2] 52 d7 [2] 15 d5 [2] 52 c4 [2] 1c c8 [2] 10 c2 [2] 07 c9 [2] 1c 87 [2] 21 }

  condition:
    any of them
}