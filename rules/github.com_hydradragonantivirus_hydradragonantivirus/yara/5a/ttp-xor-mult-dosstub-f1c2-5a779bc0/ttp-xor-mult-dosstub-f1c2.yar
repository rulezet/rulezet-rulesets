rule TTP_XOR_MULT_DOSStub_f1c2 {
  strings:
    $key_f1c2 = { a5 aa [2] d1 b2 [2] 96 b0 [2] d1 a1 [2] 9f ad [2] 93 a7 [2] 84 ac [2] 9f e2 [2] a2 }

  condition:
    any of them
}