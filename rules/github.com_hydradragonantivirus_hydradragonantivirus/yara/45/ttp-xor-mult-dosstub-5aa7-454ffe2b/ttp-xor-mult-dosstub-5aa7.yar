rule TTP_XOR_MULT_DOSStub_5aa7 {
  strings:
    $key_5aa7 = { 0e cf [2] 7a d7 [2] 3d d5 [2] 7a c4 [2] 34 c8 [2] 38 c2 [2] 2f c9 [2] 34 87 [2] 09 }

  condition:
    any of them
}