rule TTP_XOR_MULT_DOSStub_efaa {
  strings:
    $key_efaa = { bb c2 [2] cf da [2] 88 d8 [2] cf c9 [2] 81 c5 [2] 8d cf [2] 9a c4 [2] 81 8a [2] bc }

  condition:
    any of them
}