rule TTP_XOR_MULT_DOSStub_e7c2 {
  strings:
    $key_e7c2 = { b3 aa [2] c7 b2 [2] 80 b0 [2] c7 a1 [2] 89 ad [2] 85 a7 [2] 92 ac [2] 89 e2 [2] b4 }

  condition:
    any of them
}