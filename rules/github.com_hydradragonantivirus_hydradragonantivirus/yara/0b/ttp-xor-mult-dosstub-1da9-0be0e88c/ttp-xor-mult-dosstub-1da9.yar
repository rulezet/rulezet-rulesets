rule TTP_XOR_MULT_DOSStub_1da9 {
  strings:
    $key_1da9 = { 49 c1 [2] 3d d9 [2] 7a db [2] 3d ca [2] 73 c6 [2] 7f cc [2] 68 c7 [2] 73 89 [2] 4e }

  condition:
    any of them
}