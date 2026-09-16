rule TTP_XOR_MULT_DOSStub_39b3 {
  strings:
    $key_39b3 = { 6d db [2] 19 c3 [2] 5e c1 [2] 19 d0 [2] 57 dc [2] 5b d6 [2] 4c dd [2] 57 93 [2] 6a }

  condition:
    any of them
}