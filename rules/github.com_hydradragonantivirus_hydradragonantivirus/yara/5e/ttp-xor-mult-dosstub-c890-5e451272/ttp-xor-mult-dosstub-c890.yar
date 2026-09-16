rule TTP_XOR_MULT_DOSStub_c890 {
  strings:
    $key_c890 = { 9c f8 [2] e8 e0 [2] af e2 [2] e8 f3 [2] a6 ff [2] aa f5 [2] bd fe [2] a6 b0 [2] 9b }

  condition:
    any of them
}