rule TTP_XOR_MULT_DOSStub_e8b9 {
  strings:
    $key_e8b9 = { bc d1 [2] c8 c9 [2] 8f cb [2] c8 da [2] 86 d6 [2] 8a dc [2] 9d d7 [2] 86 99 [2] bb }

  condition:
    any of them
}