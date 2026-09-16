rule TTP_XOR_MULT_DOSStub_2180 {
  strings:
    $key_2180 = { 75 e8 [2] 01 f0 [2] 46 f2 [2] 01 e3 [2] 4f ef [2] 43 e5 [2] 54 ee [2] 4f a0 [2] 72 }

  condition:
    any of them
}