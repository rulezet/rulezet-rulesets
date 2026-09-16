rule TTP_XOR_MULT_DOSStub_3284 {
  strings:
    $key_3284 = { 66 ec [2] 12 f4 [2] 55 f6 [2] 12 e7 [2] 5c eb [2] 50 e1 [2] 47 ea [2] 5c a4 [2] 61 }

  condition:
    any of them
}