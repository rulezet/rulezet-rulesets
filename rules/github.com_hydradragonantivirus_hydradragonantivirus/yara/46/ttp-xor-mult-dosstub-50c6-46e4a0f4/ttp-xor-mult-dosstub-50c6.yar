rule TTP_XOR_MULT_DOSStub_50c6 {
  strings:
    $key_50c6 = { 04 ae [2] 70 b6 [2] 37 b4 [2] 70 a5 [2] 3e a9 [2] 32 a3 [2] 25 a8 [2] 3e e6 [2] 03 }

  condition:
    any of them
}