rule TTP_XOR_MULT_DOSStub_20c2 {
  strings:
    $key_20c2 = { 74 aa [2] 00 b2 [2] 47 b0 [2] 00 a1 [2] 4e ad [2] 42 a7 [2] 55 ac [2] 4e e2 [2] 73 }

  condition:
    any of them
}