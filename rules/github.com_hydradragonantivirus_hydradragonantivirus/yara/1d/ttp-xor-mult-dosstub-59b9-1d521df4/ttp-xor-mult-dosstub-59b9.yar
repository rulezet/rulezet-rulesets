rule TTP_XOR_MULT_DOSStub_59b9 {
  strings:
    $key_59b9 = { 0d d1 [2] 79 c9 [2] 3e cb [2] 79 da [2] 37 d6 [2] 3b dc [2] 2c d7 [2] 37 99 [2] 0a }

  condition:
    any of them
}