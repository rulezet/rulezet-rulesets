rule TTP_XOR_MULT_DOSStub_35c2 {
  strings:
    $key_35c2 = { 61 aa [2] 15 b2 [2] 52 b0 [2] 15 a1 [2] 5b ad [2] 57 a7 [2] 40 ac [2] 5b e2 [2] 66 }

  condition:
    any of them
}