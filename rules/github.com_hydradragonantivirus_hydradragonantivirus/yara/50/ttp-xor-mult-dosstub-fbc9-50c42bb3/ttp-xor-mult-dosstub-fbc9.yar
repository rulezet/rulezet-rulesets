rule TTP_XOR_MULT_DOSStub_fbc9 {
  strings:
    $key_fbc9 = { af a1 [2] db b9 [2] 9c bb [2] db aa [2] 95 a6 [2] 99 ac [2] 8e a7 [2] 95 e9 [2] a8 }

  condition:
    any of them
}