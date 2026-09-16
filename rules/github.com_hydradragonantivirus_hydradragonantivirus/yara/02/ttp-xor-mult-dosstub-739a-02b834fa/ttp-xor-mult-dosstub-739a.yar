rule TTP_XOR_MULT_DOSStub_739a {
  strings:
    $key_739a = { 27 f2 [2] 53 ea [2] 14 e8 [2] 53 f9 [2] 1d f5 [2] 11 ff [2] 06 f4 [2] 1d ba [2] 20 }

  condition:
    any of them
}