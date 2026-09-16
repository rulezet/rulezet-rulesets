rule TTP_XOR_MULT_DOSStub_60c4 {
  strings:
    $key_60c4 = { 34 ac [2] 40 b4 [2] 07 b6 [2] 40 a7 [2] 0e ab [2] 02 a1 [2] 15 aa [2] 0e e4 [2] 33 }

  condition:
    any of them
}