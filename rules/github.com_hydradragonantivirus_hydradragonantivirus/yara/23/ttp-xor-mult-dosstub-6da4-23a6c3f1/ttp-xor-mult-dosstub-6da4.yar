rule TTP_XOR_MULT_DOSStub_6da4 {
  strings:
    $key_6da4 = { 39 cc [2] 4d d4 [2] 0a d6 [2] 4d c7 [2] 03 cb [2] 0f c1 [2] 18 ca [2] 03 84 [2] 3e }

  condition:
    any of them
}