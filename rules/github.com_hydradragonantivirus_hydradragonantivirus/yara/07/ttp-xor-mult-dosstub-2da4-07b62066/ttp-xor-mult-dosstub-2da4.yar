rule TTP_XOR_MULT_DOSStub_2da4 {
  strings:
    $key_2da4 = { 79 cc [2] 0d d4 [2] 4a d6 [2] 0d c7 [2] 43 cb [2] 4f c1 [2] 58 ca [2] 43 84 [2] 7e }

  condition:
    any of them
}