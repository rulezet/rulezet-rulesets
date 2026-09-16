rule TTP_XOR_MULT_DOSStub_06c0 {
  strings:
    $key_06c0 = { 52 a8 [2] 26 b0 [2] 61 b2 [2] 26 a3 [2] 68 af [2] 64 a5 [2] 73 ae [2] 68 e0 [2] 55 }

  condition:
    any of them
}