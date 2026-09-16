rule TTP_XOR_MULT_DOSStub_bc8b {
  strings:
    $key_bc8b = { e8 e3 [2] 9c fb [2] db f9 [2] 9c e8 [2] d2 e4 [2] de ee [2] c9 e5 [2] d2 ab [2] ef }

  condition:
    any of them
}