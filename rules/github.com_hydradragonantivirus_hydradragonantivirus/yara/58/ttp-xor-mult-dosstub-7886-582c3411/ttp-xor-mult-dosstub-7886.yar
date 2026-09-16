rule TTP_XOR_MULT_DOSStub_7886 {
  strings:
    $key_7886 = { 2c ee [2] 58 f6 [2] 1f f4 [2] 58 e5 [2] 16 e9 [2] 1a e3 [2] 0d e8 [2] 16 a6 [2] 2b }

  condition:
    any of them
}