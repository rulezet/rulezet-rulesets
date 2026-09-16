rule TTP_XOR_MULT_DOSStub_e996 {
  strings:
    $key_e996 = { bd fe [2] c9 e6 [2] 8e e4 [2] c9 f5 [2] 87 f9 [2] 8b f3 [2] 9c f8 [2] 87 b6 [2] ba }

  condition:
    any of them
}