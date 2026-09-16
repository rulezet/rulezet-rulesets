rule TTP_XOR_MULT_DOSStub_03d5 {
  strings:
    $key_03d5 = { 57 bd [2] 23 a5 [2] 64 a7 [2] 23 b6 [2] 6d ba [2] 61 b0 [2] 76 bb [2] 6d f5 [2] 50 }

  condition:
    any of them
}