rule TTP_XOR_MULT_DOSStub_66d5 {
  strings:
    $key_66d5 = { 32 bd [2] 46 a5 [2] 01 a7 [2] 46 b6 [2] 08 ba [2] 04 b0 [2] 13 bb [2] 08 f5 [2] 35 }

  condition:
    any of them
}