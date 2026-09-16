rule TTP_XOR_MULT_DOSStub_5eb5 {
  strings:
    $key_5eb5 = { 0a dd [2] 7e c5 [2] 39 c7 [2] 7e d6 [2] 30 da [2] 3c d0 [2] 2b db [2] 30 95 [2] 0d }

  condition:
    any of them
}