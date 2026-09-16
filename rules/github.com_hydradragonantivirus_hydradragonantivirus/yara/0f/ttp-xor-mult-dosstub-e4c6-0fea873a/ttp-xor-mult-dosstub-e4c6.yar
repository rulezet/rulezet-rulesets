rule TTP_XOR_MULT_DOSStub_e4c6 {
  strings:
    $key_e4c6 = { b0 ae [2] c4 b6 [2] 83 b4 [2] c4 a5 [2] 8a a9 [2] 86 a3 [2] 91 a8 [2] 8a e6 [2] b7 }

  condition:
    any of them
}