rule TTP_XOR_MULT_DOSStub_1886 {
  strings:
    $key_1886 = { 4c ee [2] 38 f6 [2] 7f f4 [2] 38 e5 [2] 76 e9 [2] 7a e3 [2] 6d e8 [2] 76 a6 [2] 4b }

  condition:
    any of them
}