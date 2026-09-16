rule TTP_XOR_MULT_DOSStub_4ad0 {
  strings:
    $key_4ad0 = { 1e b8 [2] 6a a0 [2] 2d a2 [2] 6a b3 [2] 24 bf [2] 28 b5 [2] 3f be [2] 24 f0 [2] 19 }

  condition:
    any of them
}