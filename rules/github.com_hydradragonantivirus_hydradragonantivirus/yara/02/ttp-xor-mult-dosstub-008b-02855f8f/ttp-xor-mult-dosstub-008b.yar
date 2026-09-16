rule TTP_XOR_MULT_DOSStub_008b {
  strings:
    $key_008b = { 54 e3 [2] 20 fb [2] 67 f9 [2] 20 e8 [2] 6e e4 [2] 62 ee [2] 75 e5 [2] 6e ab [2] 53 }

  condition:
    any of them
}