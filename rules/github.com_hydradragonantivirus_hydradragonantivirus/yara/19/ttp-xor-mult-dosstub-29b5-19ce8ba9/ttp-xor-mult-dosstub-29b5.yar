rule TTP_XOR_MULT_DOSStub_29b5 {
  strings:
    $key_29b5 = { 7d dd [2] 09 c5 [2] 4e c7 [2] 09 d6 [2] 47 da [2] 4b d0 [2] 5c db [2] 47 95 [2] 7a }

  condition:
    any of them
}