rule TTP_XOR_MULT_DOSStub_1aa4 {
  strings:
    $key_1aa4 = { 4e cc [2] 3a d4 [2] 7d d6 [2] 3a c7 [2] 74 cb [2] 78 c1 [2] 6f ca [2] 74 84 [2] 49 }

  condition:
    any of them
}