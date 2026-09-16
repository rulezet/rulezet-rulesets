rule TTP_XOR_MULT_DOSStub_e8a9 {
  strings:
    $key_e8a9 = { bc c1 [2] c8 d9 [2] 8f db [2] c8 ca [2] 86 c6 [2] 8a cc [2] 9d c7 [2] 86 89 [2] bb }

  condition:
    any of them
}