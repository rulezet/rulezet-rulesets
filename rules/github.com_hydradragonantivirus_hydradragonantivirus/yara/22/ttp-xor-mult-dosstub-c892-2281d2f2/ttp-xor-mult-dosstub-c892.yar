rule TTP_XOR_MULT_DOSStub_c892 {
  strings:
    $key_c892 = { 9c fa [2] e8 e2 [2] af e0 [2] e8 f1 [2] a6 fd [2] aa f7 [2] bd fc [2] a6 b2 [2] 9b }

  condition:
    any of them
}