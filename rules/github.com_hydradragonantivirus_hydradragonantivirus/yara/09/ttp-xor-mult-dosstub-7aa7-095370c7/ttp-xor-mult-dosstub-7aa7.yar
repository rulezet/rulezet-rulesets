rule TTP_XOR_MULT_DOSStub_7aa7 {
  strings:
    $key_7aa7 = { 2e cf [2] 5a d7 [2] 1d d5 [2] 5a c4 [2] 14 c8 [2] 18 c2 [2] 0f c9 [2] 14 87 [2] 29 }

  condition:
    any of them
}