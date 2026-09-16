rule TTP_XOR_MULT_DOSStub_efcb {
  strings:
    $key_efcb = { bb a3 [2] cf bb [2] 88 b9 [2] cf a8 [2] 81 a4 [2] 8d ae [2] 9a a5 [2] 81 eb [2] bc }

  condition:
    any of them
}