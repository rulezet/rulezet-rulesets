rule TTP_XOR_MULT_DOSStub_5ad9 {
  strings:
    $key_5ad9 = { 0e b1 [2] 7a a9 [2] 3d ab [2] 7a ba [2] 34 b6 [2] 38 bc [2] 2f b7 [2] 34 f9 [2] 09 }

  condition:
    any of them
}