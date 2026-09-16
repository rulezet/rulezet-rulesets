rule TTP_XOR_MULT_DOSStub_0886 {
  strings:
    $key_0886 = { 5c ee [2] 28 f6 [2] 6f f4 [2] 28 e5 [2] 66 e9 [2] 6a e3 [2] 7d e8 [2] 66 a6 [2] 5b }

  condition:
    any of them
}