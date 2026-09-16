rule TTP_XOR_MULT_DOSStub_28b5 {
  strings:
    $key_28b5 = { 7c dd [2] 08 c5 [2] 4f c7 [2] 08 d6 [2] 46 da [2] 4a d0 [2] 5d db [2] 46 95 [2] 7b }

  condition:
    any of them
}