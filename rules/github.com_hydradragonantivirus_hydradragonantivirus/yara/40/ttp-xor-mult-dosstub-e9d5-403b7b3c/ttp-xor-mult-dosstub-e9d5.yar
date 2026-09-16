rule TTP_XOR_MULT_DOSStub_e9d5 {
  strings:
    $key_e9d5 = { bd bd [2] c9 a5 [2] 8e a7 [2] c9 b6 [2] 87 ba [2] 8b b0 [2] 9c bb [2] 87 f5 [2] ba }

  condition:
    any of them
}