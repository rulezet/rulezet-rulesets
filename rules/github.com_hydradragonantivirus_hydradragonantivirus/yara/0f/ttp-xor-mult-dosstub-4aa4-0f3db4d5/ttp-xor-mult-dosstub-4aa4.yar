rule TTP_XOR_MULT_DOSStub_4aa4 {
  strings:
    $key_4aa4 = { 1e cc [2] 6a d4 [2] 2d d6 [2] 6a c7 [2] 24 cb [2] 28 c1 [2] 3f ca [2] 24 84 [2] 19 }

  condition:
    any of them
}