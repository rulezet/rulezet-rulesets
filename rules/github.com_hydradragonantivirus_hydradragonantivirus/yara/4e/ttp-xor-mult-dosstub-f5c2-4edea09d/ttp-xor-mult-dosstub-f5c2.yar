rule TTP_XOR_MULT_DOSStub_f5c2 {
  strings:
    $key_f5c2 = { a1 aa [2] d5 b2 [2] 92 b0 [2] d5 a1 [2] 9b ad [2] 97 a7 [2] 80 ac [2] 9b e2 [2] a6 }

  condition:
    any of them
}