rule TTP_XOR_MULT_DOSStub_64d0 {
  strings:
    $key_64d0 = { 30 b8 [2] 44 a0 [2] 03 a2 [2] 44 b3 [2] 0a bf [2] 06 b5 [2] 11 be [2] 0a f0 [2] 37 }

  condition:
    any of them
}