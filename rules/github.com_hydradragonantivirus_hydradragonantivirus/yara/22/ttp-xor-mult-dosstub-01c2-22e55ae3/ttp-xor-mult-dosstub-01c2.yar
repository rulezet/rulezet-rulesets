rule TTP_XOR_MULT_DOSStub_01c2 {
  strings:
    $key_01c2 = { 55 aa [2] 21 b2 [2] 66 b0 [2] 21 a1 [2] 6f ad [2] 63 a7 [2] 74 ac [2] 6f e2 [2] 52 }

  condition:
    any of them
}