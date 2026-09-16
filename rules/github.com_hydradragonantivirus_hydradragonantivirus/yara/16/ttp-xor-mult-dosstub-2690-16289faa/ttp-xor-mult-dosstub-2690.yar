rule TTP_XOR_MULT_DOSStub_2690 {
  strings:
    $key_2690 = { 72 f8 [2] 06 e0 [2] 41 e2 [2] 06 f3 [2] 48 ff [2] 44 f5 [2] 53 fe [2] 48 b0 [2] 75 }

  condition:
    any of them
}