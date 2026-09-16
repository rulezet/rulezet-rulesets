rule TTP_XOR_MULT_DOSStub_378f {
  strings:
    $key_378f = { 63 e7 [2] 17 ff [2] 50 fd [2] 17 ec [2] 59 e0 [2] 55 ea [2] 42 e1 [2] 59 af [2] 64 }

  condition:
    any of them
}