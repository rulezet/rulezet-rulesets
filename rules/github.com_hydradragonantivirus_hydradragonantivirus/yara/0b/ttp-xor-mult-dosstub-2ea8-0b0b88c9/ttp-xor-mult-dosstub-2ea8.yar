rule TTP_XOR_MULT_DOSStub_2ea8 {
  strings:
    $key_2ea8 = { 7a c0 [2] 0e d8 [2] 49 da [2] 0e cb [2] 40 c7 [2] 4c cd [2] 5b c6 [2] 40 88 [2] 7d }

  condition:
    any of them
}