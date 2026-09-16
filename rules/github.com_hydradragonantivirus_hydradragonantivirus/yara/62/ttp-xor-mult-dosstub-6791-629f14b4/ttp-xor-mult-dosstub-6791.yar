rule TTP_XOR_MULT_DOSStub_6791 {
  strings:
    $key_6791 = { 33 f9 [2] 47 e1 [2] 00 e3 [2] 47 f2 [2] 09 fe [2] 05 f4 [2] 12 ff [2] 09 b1 [2] 34 }

  condition:
    any of them
}