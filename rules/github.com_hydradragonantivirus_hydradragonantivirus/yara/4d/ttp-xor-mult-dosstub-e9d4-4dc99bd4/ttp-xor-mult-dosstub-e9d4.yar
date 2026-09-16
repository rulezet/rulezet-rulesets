rule TTP_XOR_MULT_DOSStub_e9d4 {
  strings:
    $key_e9d4 = { bd bc [2] c9 a4 [2] 8e a6 [2] c9 b7 [2] 87 bb [2] 8b b1 [2] 9c ba [2] 87 f4 [2] ba }

  condition:
    any of them
}