rule TTP_XOR_MULT_DOSStub_60c9 {
  strings:
    $key_60c9 = { 34 a1 [2] 40 b9 [2] 07 bb [2] 40 aa [2] 0e a6 [2] 02 ac [2] 15 a7 [2] 0e e9 [2] 33 }

  condition:
    any of them
}