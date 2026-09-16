rule TTP_XOR_MULT_DOSStub_e4c0 {
  strings:
    $key_e4c0 = { b0 a8 [2] c4 b0 [2] 83 b2 [2] c4 a3 [2] 8a af [2] 86 a5 [2] 91 ae [2] 8a e0 [2] b7 }

  condition:
    any of them
}