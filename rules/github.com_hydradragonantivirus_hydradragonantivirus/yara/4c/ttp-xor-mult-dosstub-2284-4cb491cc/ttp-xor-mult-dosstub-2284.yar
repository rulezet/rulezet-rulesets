rule TTP_XOR_MULT_DOSStub_2284 {
  strings:
    $key_2284 = { 76 ec [2] 02 f4 [2] 45 f6 [2] 02 e7 [2] 4c eb [2] 40 e1 [2] 57 ea [2] 4c a4 [2] 71 }

  condition:
    any of them
}