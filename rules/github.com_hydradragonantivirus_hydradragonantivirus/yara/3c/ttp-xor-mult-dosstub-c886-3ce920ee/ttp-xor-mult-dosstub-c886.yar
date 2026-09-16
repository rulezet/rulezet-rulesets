rule TTP_XOR_MULT_DOSStub_c886 {
  strings:
    $key_c886 = { 9c ee [2] e8 f6 [2] af f4 [2] e8 e5 [2] a6 e9 [2] aa e3 [2] bd e8 [2] a6 a6 [2] 9b }

  condition:
    any of them
}