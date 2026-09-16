rule TTP_XOR_MULT_DOSStub_2ab5 {
  strings:
    $key_2ab5 = { 7e dd [2] 0a c5 [2] 4d c7 [2] 0a d6 [2] 44 da [2] 48 d0 [2] 5f db [2] 44 95 [2] 79 }

  condition:
    any of them
}