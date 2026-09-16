rule TTP_XOR_MULT_DOSStub_51c2 {
  strings:
    $key_51c2 = { 05 aa [2] 71 b2 [2] 36 b0 [2] 71 a1 [2] 3f ad [2] 33 a7 [2] 24 ac [2] 3f e2 [2] 02 }

  condition:
    any of them
}