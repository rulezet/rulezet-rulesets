rule TTP_XOR_MULT_DOSStub_cfc3 {
  strings:
    $key_cfc3 = { 9b ab [2] ef b3 [2] a8 b1 [2] ef a0 [2] a1 ac [2] ad a6 [2] ba ad [2] a1 e3 [2] 9c }

  condition:
    any of them
}