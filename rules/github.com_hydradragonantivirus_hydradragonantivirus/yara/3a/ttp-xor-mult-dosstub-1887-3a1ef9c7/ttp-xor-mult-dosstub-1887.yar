rule TTP_XOR_MULT_DOSStub_1887 {
  strings:
    $key_1887 = { 4c ef [2] 38 f7 [2] 7f f5 [2] 38 e4 [2] 76 e8 [2] 7a e2 [2] 6d e9 [2] 76 a7 [2] 4b }

  condition:
    any of them
}