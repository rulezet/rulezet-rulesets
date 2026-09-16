rule TTP_XOR_MULT_DOSStub_3da9 {
  strings:
    $key_3da9 = { 69 c1 [2] 1d d9 [2] 5a db [2] 1d ca [2] 53 c6 [2] 5f cc [2] 48 c7 [2] 53 89 [2] 6e }

  condition:
    any of them
}