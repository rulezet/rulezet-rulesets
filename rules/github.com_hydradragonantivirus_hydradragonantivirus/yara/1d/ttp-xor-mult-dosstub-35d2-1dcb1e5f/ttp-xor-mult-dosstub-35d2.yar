rule TTP_XOR_MULT_DOSStub_35d2 {
  strings:
    $key_35d2 = { 61 ba [2] 15 a2 [2] 52 a0 [2] 15 b1 [2] 5b bd [2] 57 b7 [2] 40 bc [2] 5b f2 [2] 66 }

  condition:
    any of them
}