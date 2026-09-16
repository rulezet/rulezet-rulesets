rule TTP_XOR_MULT_DOSStub_e9d2 {
  strings:
    $key_e9d2 = { bd ba [2] c9 a2 [2] 8e a0 [2] c9 b1 [2] 87 bd [2] 8b b7 [2] 9c bc [2] 87 f2 [2] ba }

  condition:
    any of them
}