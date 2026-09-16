rule TTP_XOR_MULT_DOSStub_baac {
  strings:
    $key_baac = { ee c4 [2] 9a dc [2] dd de [2] 9a cf [2] d4 c3 [2] d8 c9 [2] cf c2 [2] d4 8c [2] e9 }

  condition:
    any of them
}