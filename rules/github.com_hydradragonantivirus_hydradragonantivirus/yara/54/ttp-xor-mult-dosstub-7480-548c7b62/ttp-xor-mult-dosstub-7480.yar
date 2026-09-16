rule TTP_XOR_MULT_DOSStub_7480 {
  strings:
    $key_7480 = { 20 e8 [2] 54 f0 [2] 13 f2 [2] 54 e3 [2] 1a ef [2] 16 e5 [2] 01 ee [2] 1a a0 [2] 27 }

  condition:
    any of them
}