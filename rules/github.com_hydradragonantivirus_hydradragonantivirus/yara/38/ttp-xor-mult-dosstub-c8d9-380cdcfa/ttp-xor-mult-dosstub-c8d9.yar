rule TTP_XOR_MULT_DOSStub_c8d9 {
  strings:
    $key_c8d9 = { 9c b1 [2] e8 a9 [2] af ab [2] e8 ba [2] a6 b6 [2] aa bc [2] bd b7 [2] a6 f9 [2] 9b }

  condition:
    any of them
}