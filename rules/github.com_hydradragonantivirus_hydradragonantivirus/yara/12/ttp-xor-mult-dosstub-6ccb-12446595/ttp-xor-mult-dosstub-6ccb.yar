rule TTP_XOR_MULT_DOSStub_6ccb {
  strings:
    $key_6ccb = { 38 a3 [2] 4c bb [2] 0b b9 [2] 4c a8 [2] 02 a4 [2] 0e ae [2] 19 a5 [2] 02 eb [2] 3f }

  condition:
    any of them
}