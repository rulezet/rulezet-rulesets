rule TTP_XOR_MULT_DOSStub_2db9 {
  strings:
    $key_2db9 = { 79 d1 [2] 0d c9 [2] 4a cb [2] 0d da [2] 43 d6 [2] 4f dc [2] 58 d7 [2] 43 99 [2] 7e }

  condition:
    any of them
}