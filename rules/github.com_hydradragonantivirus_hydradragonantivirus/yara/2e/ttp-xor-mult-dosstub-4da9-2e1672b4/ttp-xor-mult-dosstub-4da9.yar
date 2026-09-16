rule TTP_XOR_MULT_DOSStub_4da9 {
  strings:
    $key_4da9 = { 19 c1 [2] 6d d9 [2] 2a db [2] 6d ca [2] 23 c6 [2] 2f cc [2] 38 c7 [2] 23 89 [2] 1e }

  condition:
    any of them
}