rule TTP_XOR_MULT_DOSStub_4ebe {
  strings:
    $key_4ebe = { 1a d6 [2] 6e ce [2] 29 cc [2] 6e dd [2] 20 d1 [2] 2c db [2] 3b d0 [2] 20 9e [2] 1d }

  condition:
    any of them
}