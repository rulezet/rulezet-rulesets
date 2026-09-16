rule TTP_XOR_MULT_DOSStub_15d4 {
  strings:
    $key_15d4 = { 41 bc [2] 35 a4 [2] 72 a6 [2] 35 b7 [2] 7b bb [2] 77 b1 [2] 60 ba [2] 7b f4 [2] 46 }

  condition:
    any of them
}