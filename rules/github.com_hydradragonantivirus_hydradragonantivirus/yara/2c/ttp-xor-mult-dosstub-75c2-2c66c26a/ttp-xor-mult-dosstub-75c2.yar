rule TTP_XOR_MULT_DOSStub_75c2 {
  strings:
    $key_75c2 = { 21 aa [2] 55 b2 [2] 12 b0 [2] 55 a1 [2] 1b ad [2] 17 a7 [2] 00 ac [2] 1b e2 [2] 26 }

  condition:
    any of them
}