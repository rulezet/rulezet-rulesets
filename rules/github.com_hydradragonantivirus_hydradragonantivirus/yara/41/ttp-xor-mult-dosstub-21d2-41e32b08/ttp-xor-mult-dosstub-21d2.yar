rule TTP_XOR_MULT_DOSStub_21d2 {
  strings:
    $key_21d2 = { 75 ba [2] 01 a2 [2] 46 a0 [2] 01 b1 [2] 4f bd [2] 43 b7 [2] 54 bc [2] 4f f2 [2] 72 }

  condition:
    any of them
}