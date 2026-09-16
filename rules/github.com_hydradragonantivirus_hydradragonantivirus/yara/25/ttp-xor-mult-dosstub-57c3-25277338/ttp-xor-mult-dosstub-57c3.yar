rule TTP_XOR_MULT_DOSStub_57c3 {
  strings:
    $key_57c3 = { 03 ab [2] 77 b3 [2] 30 b1 [2] 77 a0 [2] 39 ac [2] 35 a6 [2] 22 ad [2] 39 e3 [2] 04 }

  condition:
    any of them
}