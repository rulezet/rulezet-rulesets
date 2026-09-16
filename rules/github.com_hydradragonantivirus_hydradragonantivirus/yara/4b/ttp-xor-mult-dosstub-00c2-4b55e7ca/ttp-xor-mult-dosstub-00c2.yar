rule TTP_XOR_MULT_DOSStub_00c2 {
  strings:
    $key_00c2 = { 54 aa [2] 20 b2 [2] 67 b0 [2] 20 a1 [2] 6e ad [2] 62 a7 [2] 75 ac [2] 6e e2 [2] 53 }

  condition:
    any of them
}