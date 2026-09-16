rule TTP_XOR_MULT_DOSStub_c6c5 {
  strings:
    $key_c6c5 = { 92 ad [2] e6 b5 [2] a1 b7 [2] e6 a6 [2] a8 aa [2] a4 a0 [2] b3 ab [2] a8 e5 [2] 95 }

  condition:
    any of them
}