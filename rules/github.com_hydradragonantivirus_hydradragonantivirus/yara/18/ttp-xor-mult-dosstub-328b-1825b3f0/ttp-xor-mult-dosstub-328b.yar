rule TTP_XOR_MULT_DOSStub_328b {
  strings:
    $key_328b = { 66 e3 [2] 12 fb [2] 55 f9 [2] 12 e8 [2] 5c e4 [2] 50 ee [2] 47 e5 [2] 5c ab [2] 61 }

  condition:
    any of them
}