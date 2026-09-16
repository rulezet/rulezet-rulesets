rule TTP_XOR_MULT_DOSStub_34d5 {
  strings:
    $key_34d5 = { 60 bd [2] 14 a5 [2] 53 a7 [2] 14 b6 [2] 5a ba [2] 56 b0 [2] 41 bb [2] 5a f5 [2] 67 }

  condition:
    any of them
}