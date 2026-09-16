rule TTP_XOR_MULT_DOSStub_15d2 {
  strings:
    $key_15d2 = { 41 ba [2] 35 a2 [2] 72 a0 [2] 35 b1 [2] 7b bd [2] 77 b7 [2] 60 bc [2] 7b f2 [2] 46 }

  condition:
    any of them
}