rule TTP_XOR_MULT_DOSStub_4190 {
  strings:
    $key_4190 = { 15 f8 [2] 61 e0 [2] 26 e2 [2] 61 f3 [2] 2f ff [2] 23 f5 [2] 34 fe [2] 2f b0 [2] 12 }

  condition:
    any of them
}