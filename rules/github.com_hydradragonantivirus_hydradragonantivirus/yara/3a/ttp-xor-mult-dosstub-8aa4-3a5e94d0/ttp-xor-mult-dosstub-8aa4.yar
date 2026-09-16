rule TTP_XOR_MULT_DOSStub_8aa4 {
  strings:
    $key_8aa4 = { de cc [2] aa d4 [2] ed d6 [2] aa c7 [2] e4 cb [2] e8 c1 [2] ff ca [2] e4 84 [2] d9 }

  condition:
    any of them
}