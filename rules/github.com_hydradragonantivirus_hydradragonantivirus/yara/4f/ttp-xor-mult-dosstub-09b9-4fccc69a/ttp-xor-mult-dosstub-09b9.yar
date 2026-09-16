rule TTP_XOR_MULT_DOSStub_09b9 {
  strings:
    $key_09b9 = { 5d d1 [2] 29 c9 [2] 6e cb [2] 29 da [2] 67 d6 [2] 6b dc [2] 7c d7 [2] 67 99 [2] 5a }

  condition:
    any of them
}