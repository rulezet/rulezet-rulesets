rule TTP_XOR_MULT_DOSStub_05c6 {
  strings:
    $key_05c6 = { 51 ae [2] 25 b6 [2] 62 b4 [2] 25 a5 [2] 6b a9 [2] 67 a3 [2] 70 a8 [2] 6b e6 [2] 56 }

  condition:
    any of them
}