rule TTP_XOR_MULT_DOSStub_e3c0 {
  strings:
    $key_e3c0 = { b7 a8 [2] c3 b0 [2] 84 b2 [2] c3 a3 [2] 8d af [2] 81 a5 [2] 96 ae [2] 8d e0 [2] b0 }

  condition:
    any of them
}