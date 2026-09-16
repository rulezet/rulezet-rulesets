rule TTP_XOR_MULT_DOSStub_bca9 {
  strings:
    $key_bca9 = { e8 c1 [2] 9c d9 [2] db db [2] 9c ca [2] d2 c6 [2] de cc [2] c9 c7 [2] d2 89 [2] ef }

  condition:
    any of them
}