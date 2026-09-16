rule TTP_XOR_MULT_DOSStub_0090 {
  strings:
    $key_0090 = { 54 f8 [2] 20 e0 [2] 67 e2 [2] 20 f3 [2] 6e ff [2] 62 f5 [2] 75 fe [2] 6e b0 [2] 53 }

  condition:
    any of them
}