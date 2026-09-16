rule TTP_XOR_MULT_DOSStub_3aa7 {
  strings:
    $key_3aa7 = { 6e cf [2] 1a d7 [2] 5d d5 [2] 1a c4 [2] 54 c8 [2] 58 c2 [2] 4f c9 [2] 54 87 [2] 69 }

  condition:
    any of them
}