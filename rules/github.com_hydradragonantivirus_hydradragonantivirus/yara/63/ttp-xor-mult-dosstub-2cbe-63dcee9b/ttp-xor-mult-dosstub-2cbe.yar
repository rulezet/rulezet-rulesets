rule TTP_XOR_MULT_DOSStub_2cbe {
  strings:
    $key_2cbe = { 78 d6 [2] 0c ce [2] 4b cc [2] 0c dd [2] 42 d1 [2] 4e db [2] 59 d0 [2] 42 9e [2] 7f }

  condition:
    any of them
}