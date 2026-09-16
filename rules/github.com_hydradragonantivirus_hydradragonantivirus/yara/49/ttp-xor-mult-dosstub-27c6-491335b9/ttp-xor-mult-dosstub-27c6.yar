rule TTP_XOR_MULT_DOSStub_27c6 {
  strings:
    $key_27c6 = { 73 ae [2] 07 b6 [2] 40 b4 [2] 07 a5 [2] 49 a9 [2] 45 a3 [2] 52 a8 [2] 49 e6 [2] 74 }

  condition:
    any of them
}