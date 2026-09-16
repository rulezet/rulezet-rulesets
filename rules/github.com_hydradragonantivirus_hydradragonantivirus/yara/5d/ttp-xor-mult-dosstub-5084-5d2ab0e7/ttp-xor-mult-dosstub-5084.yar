rule TTP_XOR_MULT_DOSStub_5084 {
  strings:
    $key_5084 = { 04 ec [2] 70 f4 [2] 37 f6 [2] 70 e7 [2] 3e eb [2] 32 e1 [2] 25 ea [2] 3e a4 [2] 03 }

  condition:
    any of them
}