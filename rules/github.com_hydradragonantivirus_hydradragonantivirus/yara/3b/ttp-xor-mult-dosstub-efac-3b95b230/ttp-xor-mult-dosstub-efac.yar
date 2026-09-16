rule TTP_XOR_MULT_DOSStub_efac {
  strings:
    $key_efac = { bb c4 [2] cf dc [2] 88 de [2] cf cf [2] 81 c3 [2] 8d c9 [2] 9a c2 [2] 81 8c [2] bc }

  condition:
    any of them
}