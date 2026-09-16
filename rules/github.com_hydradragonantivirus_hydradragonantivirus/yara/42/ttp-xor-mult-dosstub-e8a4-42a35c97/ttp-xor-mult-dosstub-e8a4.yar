rule TTP_XOR_MULT_DOSStub_e8a4 {
  strings:
    $key_e8a4 = { bc cc [2] c8 d4 [2] 8f d6 [2] c8 c7 [2] 86 cb [2] 8a c1 [2] 9d ca [2] 86 84 [2] bb }

  condition:
    any of them
}