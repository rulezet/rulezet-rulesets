rule TTP_XOR_MULT_DOSStub_72c2 {
  strings:
    $key_72c2 = { 26 aa [2] 52 b2 [2] 15 b0 [2] 52 a1 [2] 1c ad [2] 10 a7 [2] 07 ac [2] 1c e2 [2] 21 }

  condition:
    any of them
}