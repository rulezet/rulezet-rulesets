rule TTP_XOR_MULT_DOSStub_75d4 {
  strings:
    $key_75d4 = { 21 bc [2] 55 a4 [2] 12 a6 [2] 55 b7 [2] 1b bb [2] 17 b1 [2] 00 ba [2] 1b f4 [2] 26 }

  condition:
    any of them
}