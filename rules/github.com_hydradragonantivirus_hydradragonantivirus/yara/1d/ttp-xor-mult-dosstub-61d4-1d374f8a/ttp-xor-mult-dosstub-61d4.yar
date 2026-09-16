rule TTP_XOR_MULT_DOSStub_61d4 {
  strings:
    $key_61d4 = { 35 bc [2] 41 a4 [2] 06 a6 [2] 41 b7 [2] 0f bb [2] 03 b1 [2] 14 ba [2] 0f f4 [2] 32 }

  condition:
    any of them
}