rule TTP_XOR_MULT_DOSStub_308b {
  strings:
    $key_308b = { 64 e3 [2] 10 fb [2] 57 f9 [2] 10 e8 [2] 5e e4 [2] 52 ee [2] 45 e5 [2] 5e ab [2] 63 }

  condition:
    any of them
}