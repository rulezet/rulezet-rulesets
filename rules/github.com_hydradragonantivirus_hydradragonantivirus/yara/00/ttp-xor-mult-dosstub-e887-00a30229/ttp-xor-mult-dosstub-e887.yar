rule TTP_XOR_MULT_DOSStub_e887 {
  strings:
    $key_e887 = { bc ef [2] c8 f7 [2] 8f f5 [2] c8 e4 [2] 86 e8 [2] 8a e2 [2] 9d e9 [2] 86 a7 [2] bb }

  condition:
    any of them
}