rule TTP_XOR_MULT_DOSStub_5690 {
  strings:
    $key_5690 = { 02 f8 [2] 76 e0 [2] 31 e2 [2] 76 f3 [2] 38 ff [2] 34 f5 [2] 23 fe [2] 38 b0 [2] 05 }

  condition:
    any of them
}