rule TTP_XOR_MULT_DOSStub_2aa4 {
  strings:
    $key_2aa4 = { 7e cc [2] 0a d4 [2] 4d d6 [2] 0a c7 [2] 44 cb [2] 48 c1 [2] 5f ca [2] 44 84 [2] 79 }

  condition:
    any of them
}