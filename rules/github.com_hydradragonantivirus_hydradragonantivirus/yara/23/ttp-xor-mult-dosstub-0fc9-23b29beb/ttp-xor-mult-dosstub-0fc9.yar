rule TTP_XOR_MULT_DOSStub_0fc9 {
  strings:
    $key_0fc9 = { 5b a1 [2] 2f b9 [2] 68 bb [2] 2f aa [2] 61 a6 [2] 6d ac [2] 7a a7 [2] 61 e9 [2] 5c }

  condition:
    any of them
}