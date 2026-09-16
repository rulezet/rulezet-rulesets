rule TTP_XOR_MULT_DOSStub_1aa7 {
  strings:
    $key_1aa7 = { 4e cf [2] 3a d7 [2] 7d d5 [2] 3a c4 [2] 74 c8 [2] 78 c2 [2] 6f c9 [2] 74 87 [2] 49 }

  condition:
    any of them
}