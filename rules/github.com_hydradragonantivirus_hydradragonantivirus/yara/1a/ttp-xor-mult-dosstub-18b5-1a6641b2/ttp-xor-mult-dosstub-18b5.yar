rule TTP_XOR_MULT_DOSStub_18b5 {
  strings:
    $key_18b5 = { 4c dd [2] 38 c5 [2] 7f c7 [2] 38 d6 [2] 76 da [2] 7a d0 [2] 6d db [2] 76 95 [2] 4b }

  condition:
    any of them
}