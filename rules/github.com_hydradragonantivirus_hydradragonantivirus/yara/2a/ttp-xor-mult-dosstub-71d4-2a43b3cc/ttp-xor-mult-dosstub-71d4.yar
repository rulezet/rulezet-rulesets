rule TTP_XOR_MULT_DOSStub_71d4 {
  strings:
    $key_71d4 = { 25 bc [2] 51 a4 [2] 16 a6 [2] 51 b7 [2] 1f bb [2] 13 b1 [2] 04 ba [2] 1f f4 [2] 22 }

  condition:
    any of them
}