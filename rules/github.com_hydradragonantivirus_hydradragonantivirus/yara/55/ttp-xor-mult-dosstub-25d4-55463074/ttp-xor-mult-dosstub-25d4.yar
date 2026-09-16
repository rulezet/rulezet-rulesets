rule TTP_XOR_MULT_DOSStub_25d4 {
  strings:
    $key_25d4 = { 71 bc [2] 05 a4 [2] 42 a6 [2] 05 b7 [2] 4b bb [2] 47 b1 [2] 50 ba [2] 4b f4 [2] 76 }

  condition:
    any of them
}