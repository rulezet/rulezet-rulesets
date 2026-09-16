rule TTP_XOR_MULT_DOSStub_39b5 {
  strings:
    $key_39b5 = { 6d dd [2] 19 c5 [2] 5e c7 [2] 19 d6 [2] 57 da [2] 5b d0 [2] 4c db [2] 57 95 [2] 6a }

  condition:
    any of them
}