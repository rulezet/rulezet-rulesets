rule TTP_XOR_MULT_DOSStub_45c2 {
  strings:
    $key_45c2 = { 11 aa [2] 65 b2 [2] 22 b0 [2] 65 a1 [2] 2b ad [2] 27 a7 [2] 30 ac [2] 2b e2 [2] 16 }

  condition:
    any of them
}