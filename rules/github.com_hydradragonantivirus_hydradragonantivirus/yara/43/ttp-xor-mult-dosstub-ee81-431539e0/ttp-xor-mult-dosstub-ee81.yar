rule TTP_XOR_MULT_DOSStub_ee81 {
  strings:
    $key_ee81 = { ba e9 [2] ce f1 [2] 89 f3 [2] ce e2 [2] 80 ee [2] 8c e4 [2] 9b ef [2] 80 a1 [2] bd }

  condition:
    any of them
}