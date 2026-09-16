rule TTP_XOR_MULT_DOSStub_438b {
  strings:
    $key_438b = { 17 e3 [2] 63 fb [2] 24 f9 [2] 63 e8 [2] 2d e4 [2] 21 ee [2] 36 e5 [2] 2d ab [2] 10 }

  condition:
    any of them
}