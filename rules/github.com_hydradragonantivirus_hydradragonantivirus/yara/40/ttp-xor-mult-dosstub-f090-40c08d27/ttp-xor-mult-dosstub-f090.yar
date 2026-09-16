rule TTP_XOR_MULT_DOSStub_f090 {
  strings:
    $key_f090 = { a4 f8 [2] d0 e0 [2] 97 e2 [2] d0 f3 [2] 9e ff [2] 92 f5 [2] 85 fe [2] 9e b0 [2] a3 }

  condition:
    any of them
}