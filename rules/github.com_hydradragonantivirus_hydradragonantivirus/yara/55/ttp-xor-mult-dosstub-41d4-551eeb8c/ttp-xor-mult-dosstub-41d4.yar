rule TTP_XOR_MULT_DOSStub_41d4 {
  strings:
    $key_41d4 = { 15 bc [2] 61 a4 [2] 26 a6 [2] 61 b7 [2] 2f bb [2] 23 b1 [2] 34 ba [2] 2f f4 [2] 12 }

  condition:
    any of them
}