rule TTP_XOR_MULT_DOSStub_f4b2 {
  strings:
    $key_f4b2 = { a0 da [2] d4 c2 [2] 93 c0 [2] d4 d1 [2] 9a dd [2] 96 d7 [2] 81 dc [2] 9a 92 [2] a7 }

  condition:
    any of them
}