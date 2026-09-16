rule TTP_XOR_MULT_DOSStub_faa7 {
  strings:
    $key_faa7 = { ae cf [2] da d7 [2] 9d d5 [2] da c4 [2] 94 c8 [2] 98 c2 [2] 8f c9 [2] 94 87 [2] a9 }

  condition:
    any of them
}