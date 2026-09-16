rule TTP_XOR_MULT_DOSStub_21c2 {
  strings:
    $key_21c2 = { 75 aa [2] 01 b2 [2] 46 b0 [2] 01 a1 [2] 4f ad [2] 43 a7 [2] 54 ac [2] 4f e2 [2] 72 }

  condition:
    any of them
}