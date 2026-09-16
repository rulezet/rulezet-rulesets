rule TTP_XOR_MULT_DOSStub_6886 {
  strings:
    $key_6886 = { 3c ee [2] 48 f6 [2] 0f f4 [2] 48 e5 [2] 06 e9 [2] 0a e3 [2] 1d e8 [2] 06 a6 [2] 3b }

  condition:
    any of them
}