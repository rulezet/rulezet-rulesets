rule TTP_XOR_MULT_DOSStub_31d0 {
  strings:
    $key_31d0 = { 65 b8 [2] 11 a0 [2] 56 a2 [2] 11 b3 [2] 5f bf [2] 53 b5 [2] 44 be [2] 5f f0 [2] 62 }

  condition:
    any of them
}