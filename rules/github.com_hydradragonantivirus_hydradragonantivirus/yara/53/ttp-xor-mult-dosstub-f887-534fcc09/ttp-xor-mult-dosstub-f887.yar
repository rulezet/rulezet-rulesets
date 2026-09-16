rule TTP_XOR_MULT_DOSStub_f887 {
  strings:
    $key_f887 = { ac ef [2] d8 f7 [2] 9f f5 [2] d8 e4 [2] 96 e8 [2] 9a e2 [2] 8d e9 [2] 96 a7 [2] ab }

  condition:
    any of them
}