rule TTP_XOR_MULT_DOSStub_7184 {
  strings:
    $key_7184 = { 25 ec [2] 51 f4 [2] 16 f6 [2] 51 e7 [2] 1f eb [2] 13 e1 [2] 04 ea [2] 1f a4 [2] 22 }

  condition:
    any of them
}