rule TTP_XOR_MULT_DOSStub_e8b3 {
  strings:
    $key_e8b3 = { bc db [2] c8 c3 [2] 8f c1 [2] c8 d0 [2] 86 dc [2] 8a d6 [2] 9d dd [2] 86 93 [2] bb }

  condition:
    any of them
}