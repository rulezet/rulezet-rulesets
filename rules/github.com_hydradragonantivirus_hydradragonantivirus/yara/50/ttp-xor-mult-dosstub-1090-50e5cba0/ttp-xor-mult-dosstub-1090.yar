rule TTP_XOR_MULT_DOSStub_1090 {
  strings:
    $key_1090 = { 44 f8 [2] 30 e0 [2] 77 e2 [2] 30 f3 [2] 7e ff [2] 72 f5 [2] 65 fe [2] 7e b0 [2] 43 }

  condition:
    any of them
}