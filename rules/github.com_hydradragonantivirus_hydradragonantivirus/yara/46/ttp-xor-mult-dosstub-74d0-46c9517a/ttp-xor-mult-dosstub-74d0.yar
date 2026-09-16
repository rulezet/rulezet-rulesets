rule TTP_XOR_MULT_DOSStub_74d0 {
  strings:
    $key_74d0 = { 20 b8 [2] 54 a0 [2] 13 a2 [2] 54 b3 [2] 1a bf [2] 16 b5 [2] 01 be [2] 1a f0 [2] 27 }

  condition:
    any of them
}