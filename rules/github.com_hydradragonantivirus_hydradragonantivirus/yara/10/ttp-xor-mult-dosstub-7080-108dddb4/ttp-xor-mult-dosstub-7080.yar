rule TTP_XOR_MULT_DOSStub_7080 {
  strings:
    $key_7080 = { 24 e8 [2] 50 f0 [2] 17 f2 [2] 50 e3 [2] 1e ef [2] 12 e5 [2] 05 ee [2] 1e a0 [2] 23 }

  condition:
    any of them
}