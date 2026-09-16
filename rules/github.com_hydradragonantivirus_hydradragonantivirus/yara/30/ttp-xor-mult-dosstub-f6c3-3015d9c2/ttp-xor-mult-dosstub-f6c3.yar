rule TTP_XOR_MULT_DOSStub_f6c3 {
  strings:
    $key_f6c3 = { a2 ab [2] d6 b3 [2] 91 b1 [2] d6 a0 [2] 98 ac [2] 94 a6 [2] 83 ad [2] 98 e3 [2] a5 }

  condition:
    any of them
}