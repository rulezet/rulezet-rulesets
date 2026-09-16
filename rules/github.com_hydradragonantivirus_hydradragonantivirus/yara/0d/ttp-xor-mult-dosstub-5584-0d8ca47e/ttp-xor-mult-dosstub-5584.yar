rule TTP_XOR_MULT_DOSStub_5584 {
  strings:
    $key_5584 = { 01 ec [2] 75 f4 [2] 32 f6 [2] 75 e7 [2] 3b eb [2] 37 e1 [2] 20 ea [2] 3b a4 [2] 06 }

  condition:
    any of them
}