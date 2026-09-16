rule TTP_XOR_MULT_DOSStub_2e81 {
  strings:
    $key_2e81 = { 7a e9 [2] 0e f1 [2] 49 f3 [2] 0e e2 [2] 40 ee [2] 4c e4 [2] 5b ef [2] 40 a1 [2] 7d }

  condition:
    any of them
}