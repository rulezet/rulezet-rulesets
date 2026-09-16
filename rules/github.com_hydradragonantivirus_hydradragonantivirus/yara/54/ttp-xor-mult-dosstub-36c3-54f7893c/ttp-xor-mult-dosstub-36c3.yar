rule TTP_XOR_MULT_DOSStub_36c3 {
  strings:
    $key_36c3 = { 62 ab [2] 16 b3 [2] 51 b1 [2] 16 a0 [2] 58 ac [2] 54 a6 [2] 43 ad [2] 58 e3 [2] 65 }

  condition:
    any of them
}