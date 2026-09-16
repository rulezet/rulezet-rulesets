rule TTP_XOR_MULT_DOSStub_c184 {
  strings:
    $key_c184 = { 95 ec [2] e1 f4 [2] a6 f6 [2] e1 e7 [2] af eb [2] a3 e1 [2] b4 ea [2] af a4 [2] 92 }

  condition:
    any of them
}