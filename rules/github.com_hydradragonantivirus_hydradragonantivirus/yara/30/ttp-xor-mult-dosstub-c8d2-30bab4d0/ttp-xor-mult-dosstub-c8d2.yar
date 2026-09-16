rule TTP_XOR_MULT_DOSStub_c8d2 {
  strings:
    $key_c8d2 = { 9c ba [2] e8 a2 [2] af a0 [2] e8 b1 [2] a6 bd [2] aa b7 [2] bd bc [2] a6 f2 [2] 9b }

  condition:
    any of them
}