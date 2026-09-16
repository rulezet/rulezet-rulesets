rule TTP_XOR_MULT_DOSStub_ee8b {
  strings:
    $key_ee8b = { ba e3 [2] ce fb [2] 89 f9 [2] ce e8 [2] 80 e4 [2] 8c ee [2] 9b e5 [2] 80 ab [2] bd }

  condition:
    any of them
}