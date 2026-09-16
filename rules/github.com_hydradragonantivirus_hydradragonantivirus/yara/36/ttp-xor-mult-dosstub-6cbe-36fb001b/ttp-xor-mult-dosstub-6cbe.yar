rule TTP_XOR_MULT_DOSStub_6cbe {
  strings:
    $key_6cbe = { 38 d6 [2] 4c ce [2] 0b cc [2] 4c dd [2] 02 d1 [2] 0e db [2] 19 d0 [2] 02 9e [2] 3f }

  condition:
    any of them
}