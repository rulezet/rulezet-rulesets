rule TTP_XOR_MULT_DOSStub_20c4 {
  strings:
    $key_20c4 = { 74 ac [2] 00 b4 [2] 47 b6 [2] 00 a7 [2] 4e ab [2] 42 a1 [2] 55 aa [2] 4e e4 [2] 73 }

  condition:
    any of them
}