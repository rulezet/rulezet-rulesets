rule TTP_XOR_MULT_DOSStub_e9d7 {
  strings:
    $key_e9d7 = { bd bf [2] c9 a7 [2] 8e a5 [2] c9 b4 [2] 87 b8 [2] 8b b2 [2] 9c b9 [2] 87 f7 [2] ba }

  condition:
    any of them
}