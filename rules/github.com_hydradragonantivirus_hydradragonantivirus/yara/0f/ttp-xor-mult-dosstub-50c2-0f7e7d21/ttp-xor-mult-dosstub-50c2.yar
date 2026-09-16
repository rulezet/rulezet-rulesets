rule TTP_XOR_MULT_DOSStub_50c2 {
  strings:
    $key_50c2 = { 04 aa [2] 70 b2 [2] 37 b0 [2] 70 a1 [2] 3e ad [2] 32 a7 [2] 25 ac [2] 3e e2 [2] 03 }

  condition:
    any of them
}