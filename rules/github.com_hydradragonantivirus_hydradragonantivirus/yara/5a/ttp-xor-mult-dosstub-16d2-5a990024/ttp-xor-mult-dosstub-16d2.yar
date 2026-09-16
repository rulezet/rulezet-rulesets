rule TTP_XOR_MULT_DOSStub_16d2 {
  strings:
    $key_16d2 = { 42 ba [2] 36 a2 [2] 71 a0 [2] 36 b1 [2] 78 bd [2] 74 b7 [2] 63 bc [2] 78 f2 [2] 45 }

  condition:
    any of them
}