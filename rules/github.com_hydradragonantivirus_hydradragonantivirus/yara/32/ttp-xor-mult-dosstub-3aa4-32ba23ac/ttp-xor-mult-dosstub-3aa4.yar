rule TTP_XOR_MULT_DOSStub_3aa4 {
  strings:
    $key_3aa4 = { 6e cc [2] 1a d4 [2] 5d d6 [2] 1a c7 [2] 54 cb [2] 58 c1 [2] 4f ca [2] 54 84 [2] 69 }

  condition:
    any of them
}