rule TTP_XOR_MULT_DOSStub_278d {
  strings:
    $key_278d = { 73 e5 [2] 07 fd [2] 40 ff [2] 07 ee [2] 49 e2 [2] 45 e8 [2] 52 e3 [2] 49 ad [2] 74 }

  condition:
    any of them
}