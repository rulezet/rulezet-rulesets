rule TTP_XOR_MULT_DOSStub_0ea8 {
  strings:
    $key_0ea8 = { 5a c0 [2] 2e d8 [2] 69 da [2] 2e cb [2] 60 c7 [2] 6c cd [2] 7b c6 [2] 60 88 [2] 5d }

  condition:
    any of them
}