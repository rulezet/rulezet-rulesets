rule TTP_XOR_MULT_DOSStub_378d {
  strings:
    $key_378d = { 63 e5 [2] 17 fd [2] 50 ff [2] 17 ee [2] 59 e2 [2] 55 e8 [2] 42 e3 [2] 59 ad [2] 64 }

  condition:
    any of them
}