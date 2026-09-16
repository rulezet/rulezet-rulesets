rule TTP_XOR_MULT_DOSStub_6584 {
  strings:
    $key_6584 = { 31 ec [2] 45 f4 [2] 02 f6 [2] 45 e7 [2] 0b eb [2] 07 e1 [2] 10 ea [2] 0b a4 [2] 36 }

  condition:
    any of them
}