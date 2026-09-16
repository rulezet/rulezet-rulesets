rule TTP_XOR_MULT_DOSStub_4090 {
  strings:
    $key_4090 = { 14 f8 [2] 60 e0 [2] 27 e2 [2] 60 f3 [2] 2e ff [2] 22 f5 [2] 35 fe [2] 2e b0 [2] 13 }

  condition:
    any of them
}