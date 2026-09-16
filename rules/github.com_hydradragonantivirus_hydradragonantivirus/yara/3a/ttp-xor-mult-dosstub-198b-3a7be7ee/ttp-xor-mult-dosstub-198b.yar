rule TTP_XOR_MULT_DOSStub_198b {
  strings:
    $key_198b = { 4d e3 [2] 39 fb [2] 7e f9 [2] 39 e8 [2] 77 e4 [2] 7b ee [2] 6c e5 [2] 77 ab [2] 4a }

  condition:
    any of them
}