rule TTP_XOR_MULT_DOSStub_739c {
  strings:
    $key_739c = { 27 f4 [2] 53 ec [2] 14 ee [2] 53 ff [2] 1d f3 [2] 11 f9 [2] 06 f2 [2] 1d bc [2] 20 }

  condition:
    any of them
}