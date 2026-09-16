rule TTP_XOR_MULT_DOSStub_79b9 {
  strings:
    $key_79b9 = { 2d d1 [2] 59 c9 [2] 1e cb [2] 59 da [2] 17 d6 [2] 1b dc [2] 0c d7 [2] 17 99 [2] 2a }

  condition:
    any of them
}