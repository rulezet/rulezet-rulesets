rule TTP_XOR_MULT_DOSStub_16c0 {
  strings:
    $key_16c0 = { 42 a8 [2] 36 b0 [2] 71 b2 [2] 36 a3 [2] 78 af [2] 74 a5 [2] 63 ae [2] 78 e0 [2] 45 }

  condition:
    any of them
}