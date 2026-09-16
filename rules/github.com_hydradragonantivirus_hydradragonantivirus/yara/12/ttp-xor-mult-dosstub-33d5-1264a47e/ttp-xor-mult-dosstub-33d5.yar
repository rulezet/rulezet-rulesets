rule TTP_XOR_MULT_DOSStub_33d5 {
  strings:
    $key_33d5 = { 67 bd [2] 13 a5 [2] 54 a7 [2] 13 b6 [2] 5d ba [2] 51 b0 [2] 46 bb [2] 5d f5 [2] 60 }

  condition:
    any of them
}