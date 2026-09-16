rule TTP_XOR_MULT_DOSStub_7ea8 {
  strings:
    $key_7ea8 = { 2a c0 [2] 5e d8 [2] 19 da [2] 5e cb [2] 10 c7 [2] 1c cd [2] 0b c6 [2] 10 88 [2] 2d }

  condition:
    any of them
}