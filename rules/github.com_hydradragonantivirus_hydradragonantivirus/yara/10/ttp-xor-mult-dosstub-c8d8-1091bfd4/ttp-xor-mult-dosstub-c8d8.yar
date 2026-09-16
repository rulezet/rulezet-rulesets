rule TTP_XOR_MULT_DOSStub_c8d8 {
  strings:
    $key_c8d8 = { 9c b0 [2] e8 a8 [2] af aa [2] e8 bb [2] a6 b7 [2] aa bd [2] bd b6 [2] a6 f8 [2] 9b }

  condition:
    any of them
}