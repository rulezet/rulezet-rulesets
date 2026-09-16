rule TTP_XOR_MULT_DOSStub_f8c4 {
  strings:
    $key_f8c4 = { ac ac [2] d8 b4 [2] 9f b6 [2] d8 a7 [2] 96 ab [2] 9a a1 [2] 8d aa [2] 96 e4 [2] ab }

  condition:
    any of them
}