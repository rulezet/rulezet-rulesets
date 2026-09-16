rule TTP_XOR_MULT_DOSStub_bad0 {
  strings:
    $key_bad0 = { ee b8 [2] 9a a0 [2] dd a2 [2] 9a b3 [2] d4 bf [2] d8 b5 [2] cf be [2] d4 f0 [2] e9 }

  condition:
    any of them
}