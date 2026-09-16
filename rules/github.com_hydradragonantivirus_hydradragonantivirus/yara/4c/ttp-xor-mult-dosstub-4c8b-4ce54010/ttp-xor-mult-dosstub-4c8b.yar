rule TTP_XOR_MULT_DOSStub_4c8b {
  strings:
    $key_4c8b = { 18 e3 [2] 6c fb [2] 2b f9 [2] 6c e8 [2] 22 e4 [2] 2e ee [2] 39 e5 [2] 22 ab [2] 1f }

  condition:
    any of them
}