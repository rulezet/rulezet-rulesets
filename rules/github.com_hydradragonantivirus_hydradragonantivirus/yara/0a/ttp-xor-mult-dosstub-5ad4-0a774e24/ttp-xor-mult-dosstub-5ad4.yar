rule TTP_XOR_MULT_DOSStub_5ad4 {
  strings:
    $key_5ad4 = { 0e bc [2] 7a a4 [2] 3d a6 [2] 7a b7 [2] 34 bb [2] 38 b1 [2] 2f ba [2] 34 f4 [2] 09 }

  condition:
    any of them
}