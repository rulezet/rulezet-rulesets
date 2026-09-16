rule TTP_XOR_MULT_DOSStub_e7d8 {
  strings:
    $key_e7d8 = { b3 b0 [2] c7 a8 [2] 80 aa [2] c7 bb [2] 89 b7 [2] 85 bd [2] 92 b6 [2] 89 f8 [2] b4 }

  condition:
    any of them
}