rule TTP_XOR_MULT_DOSStub_f7c3 {
  strings:
    $key_f7c3 = { a3 ab [2] d7 b3 [2] 90 b1 [2] d7 a0 [2] 99 ac [2] 95 a6 [2] 82 ad [2] 99 e3 [2] a4 }

  condition:
    any of them
}