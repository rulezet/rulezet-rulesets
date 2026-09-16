rule TTP_XOR_MULT_DOSStub_c893 {
  strings:
    $key_c893 = { 9c fb [2] e8 e3 [2] af e1 [2] e8 f0 [2] a6 fc [2] aa f6 [2] bd fd [2] a6 b3 [2] 9b }

  condition:
    any of them
}