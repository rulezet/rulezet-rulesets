rule TTP_XOR_MULT_DOSStub_0887 {
  strings:
    $key_0887 = { 5c ef [2] 28 f7 [2] 6f f5 [2] 28 e4 [2] 66 e8 [2] 6a e2 [2] 7d e9 [2] 66 a7 [2] 5b }

  condition:
    any of them
}