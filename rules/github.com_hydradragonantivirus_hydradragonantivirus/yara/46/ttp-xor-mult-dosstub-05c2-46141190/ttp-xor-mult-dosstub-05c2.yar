rule TTP_XOR_MULT_DOSStub_05c2 {
  strings:
    $key_05c2 = { 51 aa [2] 25 b2 [2] 62 b0 [2] 25 a1 [2] 6b ad [2] 67 a7 [2] 70 ac [2] 6b e2 [2] 56 }

  condition:
    any of them
}