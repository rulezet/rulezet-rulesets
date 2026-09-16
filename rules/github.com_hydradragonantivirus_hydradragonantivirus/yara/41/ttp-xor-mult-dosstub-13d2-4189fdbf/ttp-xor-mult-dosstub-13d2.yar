rule TTP_XOR_MULT_DOSStub_13d2 {
  strings:
    $key_13d2 = { 47 ba [2] 33 a2 [2] 74 a0 [2] 33 b1 [2] 7d bd [2] 71 b7 [2] 66 bc [2] 7d f2 [2] 40 }

  condition:
    any of them
}