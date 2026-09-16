rule TTP_XOR_MULT_DOSStub_65d4 {
  strings:
    $key_65d4 = { 31 bc [2] 45 a4 [2] 02 a6 [2] 45 b7 [2] 0b bb [2] 07 b1 [2] 10 ba [2] 0b f4 [2] 36 }

  condition:
    any of them
}