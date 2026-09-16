rule TTP_XOR_MULT_DOSStub_f7c4 {
  strings:
    $key_f7c4 = { a3 ac [2] d7 b4 [2] 90 b6 [2] d7 a7 [2] 99 ab [2] 95 a1 [2] 82 aa [2] 99 e4 [2] a4 }

  condition:
    any of them
}