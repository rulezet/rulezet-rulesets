rule TTP_XOR_MULT_DOSStub_21c8 {
  strings:
    $key_21c8 = { 75 a0 [2] 01 b8 [2] 46 ba [2] 01 ab [2] 4f a7 [2] 43 ad [2] 54 a6 [2] 4f e8 [2] 72 }

  condition:
    any of them
}