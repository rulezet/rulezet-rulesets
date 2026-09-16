rule TTP_XOR_MULT_DOSStub_57d5 {
  strings:
    $key_57d5 = { 03 bd [2] 77 a5 [2] 30 a7 [2] 77 b6 [2] 39 ba [2] 35 b0 [2] 22 bb [2] 39 f5 [2] 04 }

  condition:
    any of them
}