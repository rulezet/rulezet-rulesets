rule TTP_XOR_MULT_DOSStub_60c2 {
  strings:
    $key_60c2 = { 34 aa [2] 40 b2 [2] 07 b0 [2] 40 a1 [2] 0e ad [2] 02 a7 [2] 15 ac [2] 0e e2 [2] 33 }

  condition:
    any of them
}