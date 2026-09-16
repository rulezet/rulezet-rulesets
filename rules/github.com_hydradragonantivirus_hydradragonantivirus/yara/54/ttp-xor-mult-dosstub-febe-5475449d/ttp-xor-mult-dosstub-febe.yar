rule TTP_XOR_MULT_DOSStub_febe {
  strings:
    $key_febe = { aa d6 [2] de ce [2] 99 cc [2] de dd [2] 90 d1 [2] 9c db [2] 8b d0 [2] 90 9e [2] ad }

  condition:
    any of them
}