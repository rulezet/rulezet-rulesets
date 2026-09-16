rule TTP_XOR_MULT_DOSStub_06d5 {
  strings:
    $key_06d5 = { 52 bd [2] 26 a5 [2] 61 a7 [2] 26 b6 [2] 68 ba [2] 64 b0 [2] 73 bb [2] 68 f5 [2] 55 }

  condition:
    any of them
}