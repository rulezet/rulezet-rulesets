rule TTP_XOR_MULT_DOSStub_8db9 {
  strings:
    $key_8db9 = { d9 d1 [2] ad c9 [2] ea cb [2] ad da [2] e3 d6 [2] ef dc [2] f8 d7 [2] e3 99 [2] de }

  condition:
    any of them
}