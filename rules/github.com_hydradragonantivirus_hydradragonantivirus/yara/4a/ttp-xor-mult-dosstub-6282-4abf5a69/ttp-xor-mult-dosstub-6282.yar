rule TTP_XOR_MULT_DOSStub_6282 {
  strings:
    $key_6282 = { 36 ea [2] 42 f2 [2] 05 f0 [2] 42 e1 [2] 0c ed [2] 00 e7 [2] 17 ec [2] 0c a2 [2] 31 }

  condition:
    any of them
}