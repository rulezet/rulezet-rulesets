rule TTP_XOR_MULT_DOSStub_e3c5 {
  strings:
    $key_e3c5 = { b7 ad [2] c3 b5 [2] 84 b7 [2] c3 a6 [2] 8d aa [2] 81 a0 [2] 96 ab [2] 8d e5 [2] b0 }

  condition:
    any of them
}