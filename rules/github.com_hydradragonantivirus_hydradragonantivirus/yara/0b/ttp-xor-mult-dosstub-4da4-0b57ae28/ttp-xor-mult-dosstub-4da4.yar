rule TTP_XOR_MULT_DOSStub_4da4 {
  strings:
    $key_4da4 = { 19 cc [2] 6d d4 [2] 2a d6 [2] 6d c7 [2] 23 cb [2] 2f c1 [2] 38 ca [2] 23 84 [2] 1e }

  condition:
    any of them
}