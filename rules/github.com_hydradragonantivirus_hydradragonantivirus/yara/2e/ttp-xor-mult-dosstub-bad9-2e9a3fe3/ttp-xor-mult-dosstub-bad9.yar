rule TTP_XOR_MULT_DOSStub_bad9 {
  strings:
    $key_bad9 = { ee b1 [2] 9a a9 [2] dd ab [2] 9a ba [2] d4 b6 [2] d8 bc [2] cf b7 [2] d4 f9 [2] e9 }

  condition:
    any of them
}