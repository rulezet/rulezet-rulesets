rule TTP_XOR_MULT_DOSStub_06c1 {
  strings:
    $key_06c1 = { 52 a9 [2] 26 b1 [2] 61 b3 [2] 26 a2 [2] 68 ae [2] 64 a4 [2] 73 af [2] 68 e1 [2] 55 }

  condition:
    any of them
}