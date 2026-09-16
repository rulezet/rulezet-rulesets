rule TTP_XOR_MULT_DOSStub_faa4 {
  strings:
    $key_faa4 = { ae cc [2] da d4 [2] 9d d6 [2] da c7 [2] 94 cb [2] 98 c1 [2] 8f ca [2] 94 84 [2] a9 }

  condition:
    any of them
}