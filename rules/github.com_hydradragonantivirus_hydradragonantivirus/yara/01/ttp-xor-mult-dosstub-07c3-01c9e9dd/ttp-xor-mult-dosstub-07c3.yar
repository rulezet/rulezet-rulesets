rule TTP_XOR_MULT_DOSStub_07c3 {
  strings:
    $key_07c3 = { 53 ab [2] 27 b3 [2] 60 b1 [2] 27 a0 [2] 69 ac [2] 65 a6 [2] 72 ad [2] 69 e3 [2] 54 }

  condition:
    any of them
}