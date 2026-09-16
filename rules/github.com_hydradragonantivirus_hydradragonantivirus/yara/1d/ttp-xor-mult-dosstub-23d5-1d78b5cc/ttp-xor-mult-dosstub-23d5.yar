rule TTP_XOR_MULT_DOSStub_23d5 {
  strings:
    $key_23d5 = { 77 bd [2] 03 a5 [2] 44 a7 [2] 03 b6 [2] 4d ba [2] 41 b0 [2] 56 bb [2] 4d f5 [2] 70 }

  condition:
    any of them
}