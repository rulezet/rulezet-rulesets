rule TTP_XOR_MULT_DOSStub_0c8b {
  strings:
    $key_0c8b = { 58 e3 [2] 2c fb [2] 6b f9 [2] 2c e8 [2] 62 e4 [2] 6e ee [2] 79 e5 [2] 62 ab [2] 5f }

  condition:
    any of them
}