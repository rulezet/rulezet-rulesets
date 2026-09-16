rule TTP_XOR_MULT_DOSStub_11d5 {
  strings:
    $key_11d5 = { 45 bd [2] 31 a5 [2] 76 a7 [2] 31 b6 [2] 7f ba [2] 73 b0 [2] 64 bb [2] 7f f5 [2] 42 }

  condition:
    any of them
}