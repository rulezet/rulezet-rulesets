rule TTP_XOR_MULT_DOSStub_0da4 {
  strings:
    $key_0da4 = { 59 cc [2] 2d d4 [2] 6a d6 [2] 2d c7 [2] 63 cb [2] 6f c1 [2] 78 ca [2] 63 84 [2] 5e }

  condition:
    any of them
}