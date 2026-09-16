rule TTP_XOR_MULT_DOSStub_d29b {
  strings:
    $key_d29b = { 86 f3 [2] f2 eb [2] b5 e9 [2] f2 f8 [2] bc f4 [2] b0 fe [2] a7 f5 [2] bc bb [2] 81 }

  condition:
    any of them
}