rule TTP_XOR_MULT_DOSStub_e986 {
  strings:
    $key_e986 = { bd ee [2] c9 f6 [2] 8e f4 [2] c9 e5 [2] 87 e9 [2] 8b e3 [2] 9c e8 [2] 87 a6 [2] ba }

  condition:
    any of them
}