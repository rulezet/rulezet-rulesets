rule TTP_XOR_MULT_DOSStub_cab3 {
  strings:
    $key_cab3 = { 9e db [2] ea c3 [2] ad c1 [2] ea d0 [2] a4 dc [2] a8 d6 [2] bf dd [2] a4 93 [2] 99 }

  condition:
    any of them
}