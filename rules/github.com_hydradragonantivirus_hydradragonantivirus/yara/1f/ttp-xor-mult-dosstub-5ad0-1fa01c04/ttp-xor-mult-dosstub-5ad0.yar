rule TTP_XOR_MULT_DOSStub_5ad0 {
  strings:
    $key_5ad0 = { 0e b8 [2] 7a a0 [2] 3d a2 [2] 7a b3 [2] 34 bf [2] 38 b5 [2] 2f be [2] 34 f0 [2] 09 }

  condition:
    any of them
}