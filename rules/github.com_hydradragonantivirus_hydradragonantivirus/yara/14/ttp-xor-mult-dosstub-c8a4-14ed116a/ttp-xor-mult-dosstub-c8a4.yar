rule TTP_XOR_MULT_DOSStub_c8a4 {
  strings:
    $key_c8a4 = { 9c cc [2] e8 d4 [2] af d6 [2] e8 c7 [2] a6 cb [2] aa c1 [2] bd ca [2] a6 84 [2] 9b }

  condition:
    any of them
}