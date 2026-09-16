rule TTP_XOR_MULT_DOSStub_488b {
  strings:
    $key_488b = { 1c e3 [2] 68 fb [2] 2f f9 [2] 68 e8 [2] 26 e4 [2] 2a ee [2] 3d e5 [2] 26 ab [2] 1b }

  condition:
    any of them
}