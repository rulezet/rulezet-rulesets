rule TTP_XOR_MULT_DOSStub_2090 {
  strings:
    $key_2090 = { 74 f8 [2] 00 e0 [2] 47 e2 [2] 00 f3 [2] 4e ff [2] 42 f5 [2] 55 fe [2] 4e b0 [2] 73 }

  condition:
    any of them
}