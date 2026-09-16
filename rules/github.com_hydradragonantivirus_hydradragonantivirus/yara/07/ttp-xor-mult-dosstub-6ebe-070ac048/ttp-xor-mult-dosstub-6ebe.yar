rule TTP_XOR_MULT_DOSStub_6ebe {
  strings:
    $key_6ebe = { 3a d6 [2] 4e ce [2] 09 cc [2] 4e dd [2] 00 d1 [2] 0c db [2] 1b d0 [2] 00 9e [2] 3d }

  condition:
    any of them
}