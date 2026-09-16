rule TTP_XOR_MULT_DOSStub_bcbe {
  strings:
    $key_bcbe = { e8 d6 [2] 9c ce [2] db cc [2] 9c dd [2] d2 d1 [2] de db [2] c9 d0 [2] d2 9e [2] ef }

  condition:
    any of them
}