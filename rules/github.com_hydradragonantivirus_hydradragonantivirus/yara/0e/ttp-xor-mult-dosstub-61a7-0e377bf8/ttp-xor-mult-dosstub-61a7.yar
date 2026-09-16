rule TTP_XOR_MULT_DOSStub_61a7 {
  strings:
    $key_61a7 = { 35 cf [2] 41 d7 [2] 06 d5 [2] 41 c4 [2] 0f c8 [2] 03 c2 [2] 14 c9 [2] 0f 87 [2] 32 }

  condition:
    any of them
}