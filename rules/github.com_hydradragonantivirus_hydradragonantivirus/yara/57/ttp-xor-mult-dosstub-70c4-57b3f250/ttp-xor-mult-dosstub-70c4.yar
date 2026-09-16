rule TTP_XOR_MULT_DOSStub_70c4 {
  strings:
    $key_70c4 = { 24 ac [2] 50 b4 [2] 17 b6 [2] 50 a7 [2] 1e ab [2] 12 a1 [2] 05 aa [2] 1e e4 [2] 23 }

  condition:
    any of them
}