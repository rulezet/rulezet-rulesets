rule TTP_XOR_MULT_DOSStub_378b {
  strings:
    $key_378b = { 63 e3 [2] 17 fb [2] 50 f9 [2] 17 e8 [2] 59 e4 [2] 55 ee [2] 42 e5 [2] 59 ab [2] 64 }

  condition:
    any of them
}