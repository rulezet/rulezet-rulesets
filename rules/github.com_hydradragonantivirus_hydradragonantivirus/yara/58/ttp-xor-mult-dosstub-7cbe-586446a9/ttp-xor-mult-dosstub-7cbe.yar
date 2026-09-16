rule TTP_XOR_MULT_DOSStub_7cbe {
  strings:
    $key_7cbe = { 28 d6 [2] 5c ce [2] 1b cc [2] 5c dd [2] 12 d1 [2] 1e db [2] 09 d0 [2] 12 9e [2] 2f }

  condition:
    any of them
}