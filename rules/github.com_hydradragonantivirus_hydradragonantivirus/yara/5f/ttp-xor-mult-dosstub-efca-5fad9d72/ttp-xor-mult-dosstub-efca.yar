rule TTP_XOR_MULT_DOSStub_efca {
  strings:
    $key_efca = { bb a2 [2] cf ba [2] 88 b8 [2] cf a9 [2] 81 a5 [2] 8d af [2] 9a a4 [2] 81 ea [2] bc }

  condition:
    any of them
}