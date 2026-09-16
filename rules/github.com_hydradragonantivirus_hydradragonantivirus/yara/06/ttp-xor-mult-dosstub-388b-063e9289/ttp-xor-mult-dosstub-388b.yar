rule TTP_XOR_MULT_DOSStub_388b {
  strings:
    $key_388b = { 6c e3 [2] 18 fb [2] 5f f9 [2] 18 e8 [2] 56 e4 [2] 5a ee [2] 4d e5 [2] 56 ab [2] 6b }

  condition:
    any of them
}