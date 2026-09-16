rule TTP_XOR_MULT_DOSStub_26b3 {
  strings:
    $key_26b3 = { 72 db [2] 06 c3 [2] 41 c1 [2] 06 d0 [2] 48 dc [2] 44 d6 [2] 53 dd [2] 48 93 [2] 75 }

  condition:
    any of them
}