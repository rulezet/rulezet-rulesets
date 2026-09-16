rule TTP_XOR_MULT_DOSStub_2ea9 {
  strings:
    $key_2ea9 = { 7a c1 [2] 0e d9 [2] 49 db [2] 0e ca [2] 40 c6 [2] 4c cc [2] 5b c7 [2] 40 89 [2] 7d }

  condition:
    any of them
}