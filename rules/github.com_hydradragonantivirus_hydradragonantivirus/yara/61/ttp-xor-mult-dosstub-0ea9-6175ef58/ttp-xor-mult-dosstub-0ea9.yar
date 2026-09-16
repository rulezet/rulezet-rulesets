rule TTP_XOR_MULT_DOSStub_0ea9 {
  strings:
    $key_0ea9 = { 5a c1 [2] 2e d9 [2] 69 db [2] 2e ca [2] 60 c6 [2] 6c cc [2] 7b c7 [2] 60 89 [2] 5d }

  condition:
    any of them
}