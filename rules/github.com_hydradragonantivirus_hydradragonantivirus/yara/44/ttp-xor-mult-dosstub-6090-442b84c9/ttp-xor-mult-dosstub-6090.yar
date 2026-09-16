rule TTP_XOR_MULT_DOSStub_6090 {
  strings:
    $key_6090 = { 34 f8 [2] 40 e0 [2] 07 e2 [2] 40 f3 [2] 0e ff [2] 02 f5 [2] 15 fe [2] 0e b0 [2] 33 }

  condition:
    any of them
}