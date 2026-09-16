rule TTP_XOR_MULT_DOSStub_2da0 {
  strings:
    $key_2da0 = { 79 c8 [2] 0d d0 [2] 4a d2 [2] 0d c3 [2] 43 cf [2] 4f c5 [2] 58 ce [2] 43 80 [2] 7e }

  condition:
    any of them
}