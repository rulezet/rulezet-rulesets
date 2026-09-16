rule TTP_XOR_MULT_DOSStub_41c2 {
  strings:
    $key_41c2 = { 15 aa [2] 61 b2 [2] 26 b0 [2] 61 a1 [2] 2f ad [2] 23 a7 [2] 34 ac [2] 2f e2 [2] 12 }

  condition:
    any of them
}