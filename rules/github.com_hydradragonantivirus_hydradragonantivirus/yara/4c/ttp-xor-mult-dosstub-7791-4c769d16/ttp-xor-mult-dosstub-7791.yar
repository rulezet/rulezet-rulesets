rule TTP_XOR_MULT_DOSStub_7791 {
  strings:
    $key_7791 = { 23 f9 [2] 57 e1 [2] 10 e3 [2] 57 f2 [2] 19 fe [2] 15 f4 [2] 02 ff [2] 19 b1 [2] 24 }

  condition:
    any of them
}