rule TTP_XOR_MULT_DOSStub_3790 {
  strings:
    $key_3790 = { 63 f8 [2] 17 e0 [2] 50 e2 [2] 17 f3 [2] 59 ff [2] 55 f5 [2] 42 fe [2] 59 b0 [2] 64 }

  condition:
    any of them
}