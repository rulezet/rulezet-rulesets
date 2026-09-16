rule TTP_XOR_MULT_DOSStub_e4d2 {
  strings:
    $key_e4d2 = { b0 ba [2] c4 a2 [2] 83 a0 [2] c4 b1 [2] 8a bd [2] 86 b7 [2] 91 bc [2] 8a f2 [2] b7 }

  condition:
    any of them
}