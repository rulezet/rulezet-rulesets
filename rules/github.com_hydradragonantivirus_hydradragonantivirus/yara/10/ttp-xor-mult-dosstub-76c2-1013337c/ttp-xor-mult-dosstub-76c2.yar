rule TTP_XOR_MULT_DOSStub_76c2 {
  strings:
    $key_76c2 = { 22 aa [2] 56 b2 [2] 11 b0 [2] 56 a1 [2] 18 ad [2] 14 a7 [2] 03 ac [2] 18 e2 [2] 25 }

  condition:
    any of them
}