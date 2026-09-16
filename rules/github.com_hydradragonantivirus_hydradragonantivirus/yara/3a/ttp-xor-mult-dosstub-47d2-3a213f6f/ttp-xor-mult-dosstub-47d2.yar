rule TTP_XOR_MULT_DOSStub_47d2 {
  strings:
    $key_47d2 = { 13 ba [2] 67 a2 [2] 20 a0 [2] 67 b1 [2] 29 bd [2] 25 b7 [2] 32 bc [2] 29 f2 [2] 14 }

  condition:
    any of them
}