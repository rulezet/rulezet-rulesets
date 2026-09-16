rule TTP_XOR_MULT_DOSStub_e8a8 {
  strings:
    $key_e8a8 = { bc c0 [2] c8 d8 [2] 8f da [2] c8 cb [2] 86 c7 [2] 8a cd [2] 9d c6 [2] 86 88 [2] bb }

  condition:
    any of them
}