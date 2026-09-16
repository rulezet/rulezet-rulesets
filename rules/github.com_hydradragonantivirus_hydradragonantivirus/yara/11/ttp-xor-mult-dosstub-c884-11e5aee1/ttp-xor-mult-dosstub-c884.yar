rule TTP_XOR_MULT_DOSStub_c884 {
  strings:
    $key_c884 = { 9c ec [2] e8 f4 [2] af f6 [2] e8 e7 [2] a6 eb [2] aa e1 [2] bd ea [2] a6 a4 [2] 9b }

  condition:
    any of them
}