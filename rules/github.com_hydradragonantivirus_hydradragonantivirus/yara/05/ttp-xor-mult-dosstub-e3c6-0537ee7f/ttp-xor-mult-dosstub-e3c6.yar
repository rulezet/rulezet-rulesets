rule TTP_XOR_MULT_DOSStub_e3c6 {
  strings:
    $key_e3c6 = { b7 ae [2] c3 b6 [2] 84 b4 [2] c3 a5 [2] 8d a9 [2] 81 a3 [2] 96 a8 [2] 8d e6 [2] b0 }

  condition:
    any of them
}