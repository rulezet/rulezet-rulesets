rule TTP_XOR_MULT_DOSStub_3ea8 {
  strings:
    $key_3ea8 = { 6a c0 [2] 1e d8 [2] 59 da [2] 1e cb [2] 50 c7 [2] 5c cd [2] 4b c6 [2] 50 88 [2] 6d }

  condition:
    any of them
}