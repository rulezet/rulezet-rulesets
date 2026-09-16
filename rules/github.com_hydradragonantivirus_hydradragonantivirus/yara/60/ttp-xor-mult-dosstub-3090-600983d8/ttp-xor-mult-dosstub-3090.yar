rule TTP_XOR_MULT_DOSStub_3090 {
  strings:
    $key_3090 = { 64 f8 [2] 10 e0 [2] 57 e2 [2] 10 f3 [2] 5e ff [2] 52 f5 [2] 45 fe [2] 5e b0 [2] 63 }

  condition:
    any of them
}