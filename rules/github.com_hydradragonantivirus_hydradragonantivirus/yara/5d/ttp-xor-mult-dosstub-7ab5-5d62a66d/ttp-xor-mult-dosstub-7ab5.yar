rule TTP_XOR_MULT_DOSStub_7ab5 {
  strings:
    $key_7ab5 = { 2e dd [2] 5a c5 [2] 1d c7 [2] 5a d6 [2] 14 da [2] 18 d0 [2] 0f db [2] 14 95 [2] 29 }

  condition:
    any of them
}