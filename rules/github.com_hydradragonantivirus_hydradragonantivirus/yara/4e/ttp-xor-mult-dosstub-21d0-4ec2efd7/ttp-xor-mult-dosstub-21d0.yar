rule TTP_XOR_MULT_DOSStub_21d0 {
  strings:
    $key_21d0 = { 75 b8 [2] 01 a0 [2] 46 a2 [2] 01 b3 [2] 4f bf [2] 43 b5 [2] 54 be [2] 4f f0 [2] 72 }

  condition:
    any of them
}