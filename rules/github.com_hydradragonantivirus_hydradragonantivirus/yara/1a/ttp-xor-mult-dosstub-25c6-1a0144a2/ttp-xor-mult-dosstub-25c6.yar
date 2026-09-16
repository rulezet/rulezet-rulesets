rule TTP_XOR_MULT_DOSStub_25c6 {
  strings:
    $key_25c6 = { 71 ae [2] 05 b6 [2] 42 b4 [2] 05 a5 [2] 4b a9 [2] 47 a3 [2] 50 a8 [2] 4b e6 [2] 76 }

  condition:
    any of them
}