rule TTP_XOR_MULT_DOSStub_c0c5 {
  strings:
    $key_c0c5 = { 94 ad [2] e0 b5 [2] a7 b7 [2] e0 a6 [2] ae aa [2] a2 a0 [2] b5 ab [2] ae e5 [2] 93 }

  condition:
    any of them
}