rule TTP_XOR_MULT_DOSStub_36c0 {
  strings:
    $key_36c0 = { 62 a8 [2] 16 b0 [2] 51 b2 [2] 16 a3 [2] 58 af [2] 54 a5 [2] 43 ae [2] 58 e0 [2] 65 }

  condition:
    any of them
}