rule TTP_XOR_MULT_DOSStub_6fc9 {
  strings:
    $key_6fc9 = { 3b a1 [2] 4f b9 [2] 08 bb [2] 4f aa [2] 01 a6 [2] 0d ac [2] 1a a7 [2] 01 e9 [2] 3c }

  condition:
    any of them
}