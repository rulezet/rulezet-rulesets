rule TTP_XOR_MULT_DOSStub_608b {
  strings:
    $key_608b = { 34 e3 [2] 40 fb [2] 07 f9 [2] 40 e8 [2] 0e e4 [2] 02 ee [2] 15 e5 [2] 0e ab [2] 33 }

  condition:
    any of them
}