rule TTP_XOR_MULT_DOSStub_098b {
  strings:
    $key_098b = { 5d e3 [2] 29 fb [2] 6e f9 [2] 29 e8 [2] 67 e4 [2] 6b ee [2] 7c e5 [2] 67 ab [2] 5a }

  condition:
    any of them
}