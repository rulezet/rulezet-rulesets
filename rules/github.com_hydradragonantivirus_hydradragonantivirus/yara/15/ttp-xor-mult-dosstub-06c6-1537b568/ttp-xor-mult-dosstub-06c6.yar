rule TTP_XOR_MULT_DOSStub_06c6 {
  strings:
    $key_06c6 = { 52 ae [2] 26 b6 [2] 61 b4 [2] 26 a5 [2] 68 a9 [2] 64 a3 [2] 73 a8 [2] 68 e6 [2] 55 }

  condition:
    any of them
}