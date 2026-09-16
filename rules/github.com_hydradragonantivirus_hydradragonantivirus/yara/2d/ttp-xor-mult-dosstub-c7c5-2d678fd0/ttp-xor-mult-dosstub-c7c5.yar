rule TTP_XOR_MULT_DOSStub_c7c5 {
  strings:
    $key_c7c5 = { 93 ad [2] e7 b5 [2] a0 b7 [2] e7 a6 [2] a9 aa [2] a5 a0 [2] b2 ab [2] a9 e5 [2] 94 }

  condition:
    any of them
}