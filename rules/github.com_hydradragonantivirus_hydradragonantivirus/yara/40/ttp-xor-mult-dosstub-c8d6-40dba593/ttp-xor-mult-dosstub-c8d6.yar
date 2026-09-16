rule TTP_XOR_MULT_DOSStub_c8d6 {
  strings:
    $key_c8d6 = { 9c be [2] e8 a6 [2] af a4 [2] e8 b5 [2] a6 b9 [2] aa b3 [2] bd b8 [2] a6 f6 [2] 9b }

  condition:
    any of them
}