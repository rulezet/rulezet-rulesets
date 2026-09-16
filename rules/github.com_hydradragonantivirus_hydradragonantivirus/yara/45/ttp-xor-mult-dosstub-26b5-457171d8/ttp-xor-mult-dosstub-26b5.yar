rule TTP_XOR_MULT_DOSStub_26b5 {
  strings:
    $key_26b5 = { 72 dd [2] 06 c5 [2] 41 c7 [2] 06 d6 [2] 48 da [2] 44 d0 [2] 53 db [2] 48 95 [2] 75 }

  condition:
    any of them
}